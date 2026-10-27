//! `cmd/central/c06_scenario34_verify_ticket_test.go` — C06 scenarios 3 and 4:
//! the restore-verify resolver battery over the production seams, and the
//! restore ticket's recorded, one-use lifecycle over a real broker journal.
//!
//! WHAT IS PORTED VERBATIM. Scenario 3 keeps the refusal-passthrough battery
//! over the production [`RestoreVerifyHandlerImpl`] (absent runner, malformed
//! peer, refusal passthrough, expired receipt, usable receipt) and the
//! live-operation cardinality battery over the production
//! [`ResolvingRestoreOperationHandler`] — zero/one over a real protected
//! journal and real begun restore, two over a fixed set, inner-handler
//! reachability, and the three cardinalities answering three distinct
//! reasons. Scenario 4 keeps the whole ticket battery: issuance refusals,
//! whole-record readback, the admitted begin, the over-determined replay
//! refusal beside the admitted resume, the five-mutation / three-class
//! mismatch plan, the two expiry pairs, and the two defence-in-depth pairs
//! built by writing protected state directly.
//!
//! THE ADAPTATIONS, EACH DISCLOSED IN THE SCENARIO LOG.
//!
//! 1. THE OPERATOR SURFACE IS THE HANDLER SEAM THE HELPER INSTALLS, NOT A
//!    SOCKET. Upstream dispatches `central restore <verb>` through a real
//!    AF_UNIX socket into the helper's `Server`. The Rust port calls the
//!    production handler traits directly — the same `ResolvingRestoreOperationHandler`
//!    composition the helper installs for apply/resume/abandon and the same
//!    `RestoreVerifyHandlerImpl` for verify — so every resolution rule and
//!    refusal mapping runs in production code; only the transport hop is
//!    absent. The broker journal itself is real: [`RecoveryJournalStore`]
//!    over real protected directories, composed through the same
//!    [`Service::new`] the root restore engine uses, plus a second journal
//!    store over the same root for the issuer/inspector half, exactly as
//!    upstream composes a second `broker.Service`.
//!
//! 2. `BrokerRestoreBarrierOperations`/`BrokerRestoreTicketOperations` are
//!    `pub(crate)` inside the adapter, so the live sources here are
//!    test-local implementations of the same public traits over the real
//!    journal — `inspect_restore_barrier` for operations, and an issued-
//!    ticket enumeration that mirrors `issued_ticket_operation_ids` by
//!    reading the protected ticket records themselves. The cardinality rule
//!    under test is the production resolver's, not the source's.
//!
//! 3. THE TICKET-STATE WALK IS SHAPE-BASED, NOT TYPE-DECODED. The domain
//!    `RestoreTicket`/`RestoreOperation` deliberately do not implement
//!    `Deserialize`; upstream decodes records into them and calls
//!    `Validate`. This file identifies protected records by what they
//!    contain — a `"ticket"` member whose `ticket_id` matches for ticket
//!    records; a top-level `operation_id` plus `phase`/`last_checkpoint`
//!    for operation records — and guards every write: exactly one record
//!    must match, the previous state must be the expected one, and the
//!    journal's own readers re-validate what the walk leaves behind.
//!
//! 4. THE PG TOOL VERSION IS MEASURED OFF THE HOST for the live scenario
//!    (`pg_restore --version`), exactly as upstream; the ticket records the
//!    version the host actually carries.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::Digest;
use time::OffsetDateTime;
use uuid::Uuid;

use central_adapter_linux::broker::protected_file::ProtectedFileBackend;
use central_adapter_linux::broker::recovery_journal::RecoveryJournalStore;
use central_adapter_linux::broker::server::Service;
use central_adapter_linux::broker::signing::SigningService;
use central_adapter_linux::helper::PeerIdentity;
use central_adapter_linux::helper::protocol::Response;
use central_adapter_linux::helper::restore::{
    RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS, RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS,
    RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP, RESTORE_REFUSAL_NO_LIVE_OPERATION, RestoreAbandonHandler,
    RestoreAbandonRequest, RestoreApplyAuthorizationHandler, RestoreApplyHandler,
    RestoreApplyRequest, RestoreResumeHandler, RestoreResumeRequest, RestoreVerifyHandler,
    RestoreVerifyHandlerImpl, RestoreVerifyReceipt, RestoreVerifyRequest, RestoreVerifyResult,
    new_restore_refusal,
};
use central_adapter_linux::helper::restore_resolvers::{
    ResolvingRestoreOperationHandler, RestoreLiveOperationSource, RestoreLiveTicketSource,
};
use central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;
use central_backup::port::RestoreAdmissionFacts;
use central_backup::recovery::operation::{
    RestoreCheckpoint, RestoreOperation, RestorePhase, RestoreTicket,
};
use central_foundation::failure::Failure;

use crate::runner::runner;
use crate::scenario2::{ScenarioLog, missing_live_env};

// ---------------------------------------------------------------------------
// Scope disclosures — attached to every expectation each scenario states, as
// upstream requires (the evidence artifact carries the LAST divergence, so the
// disclosure rides on each one).
// ---------------------------------------------------------------------------

pub(crate) const SCENARIO3_SCOPE_DISCLOSURE: &str = "SCOPE, CARRIED ON EVERY DIVERGENCE THIS SCENARIO EMITS: the operator surface exercised here is the production handler seam the helper installs (ResolvingRestoreOperationHandler for apply/resume/abandon, RestoreVerifyHandlerImpl for verify), called in-process; the AF_UNIX transport hop upstream dispatches through is NOT exercised -- every resolution rule and refusal mapping runs in production code, but the socket boundary, its peer-credential read and the CLI's stdout rendering are not asserted. The protected journal IS real (broker.Service plus a second RecoveryJournalStore over the same root, the same composition the root restore engine uses), and the real live-operation cardinality cases (zero before a begin, one after) run against it; the two-candidate case is a fixed source because the journal's own single-occupancy barrier makes a second live operation unreachable, exactly as upstream states. The live-ticket source mirrors issued_ticket_operation_ids by reading the protected ticket records, because the production client adapter is crate-private. No sealed backup can be admitted on any host while the production composition supplies no throughput gate, so ticket admission facts are synthetic -- a pass establishes resolver, handler and journal behavior, NOT end-to-end admission of a real backup.";

pub(crate) const SCENARIO4_SCOPE_DISCLOSURE: &str = "SCOPE, CARRIED ON EVERY DIVERGENCE THIS SCENARIO EMITS: the broker is composed in-process through the same Service::new / RecoveryJournalStore::new constructors the root restore engine uses, at this process's own uid rather than the fixed central-runtime uid -- the barrier admission that checks for root-or-runtime is unchanged, and nothing in the journal depends on the argument. There is no peer daemon: in-process composition means the socket RPC, the daemon's credential checks and the systemd hardening that surrounds a real broker are not exercised. Ticket admission facts are synthetic because sealed backup creation is unavailable (no production throughput gate); every ticket is minted by the real journal from those facts, and every refusal is the journal's own. The protected-state edits identify records by content and rewrite exactly one member; the journal's readers re-validate what is left behind.";

/// `c06Scenario3Expect` / `c06Scenario4Expect` — an expectation is never
/// stated bare; the disclosure rides on every divergence (upstream's rule).
fn expect3(id: &str, what: impl AsRef<str>) {
    runner().attach_divergence(
        id,
        &format!("{}. {}", what.as_ref(), SCENARIO3_SCOPE_DISCLOSURE),
    );
}

fn expect4(id: &str, what: impl AsRef<str>) {
    runner().attach_divergence(
        id,
        &format!("{}. {}", what.as_ref(), SCENARIO4_SCOPE_DISCLOSURE),
    );
}

// ---------------------------------------------------------------------------
// Shared battery machinery.
// ---------------------------------------------------------------------------

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

/// `c06RestoreTicketPeerPID` — this process, which is what a helper would
/// report for a peer it had just read credentials from.
pub(crate) fn peer() -> PeerIdentity {
    PeerIdentity {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
        pid: i32::try_from(std::process::id()).unwrap_or(i32::MAX),
    }
}

/// `c06SyntheticManifestDigest` — derived, so nothing here can be mistaken
/// for a digest off a real backup.
pub(crate) fn synthetic_manifest_digest(label: &str) -> String {
    let digest =
        sha2::Sha256::digest(format!("c06-scenario-4-synthetic-manifest-{label}").as_bytes());
    format!("sha256:{}", crate::hex_lower(digest))
}

/// `c06RestoreAdmissionFacts` — the obviously synthetic admission fact set
/// every ticket in this battery is minted from.
pub(crate) fn admission_facts(tool_version: &str) -> RestoreAdmissionFacts {
    let digest = sha2::Sha256::digest(b"c06-scenario-4-synthetic-capacity-evidence");
    let hex = format!("sha256:{}", crate::hex_lower(digest));
    RestoreAdmissionFacts {
        target: central_backup::domain::TargetIdentity {
            system_id: "c06-synthetic-system".to_owned(),
            database_oid: "1".to_owned(),
            database: "central".to_owned(),
            config_hash: hex.clone(),
            epoch: 7,
        },
        target_fingerprint: hex.clone(),
        security_epoch: 2,
        restore_epoch: 3,
        config_fingerprint: hex.clone(),
        payload_epoch_id: Uuid::now_v7(),
        database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.to_owned(),
        capacity_evidence_digest: hex,
        tool_version: format!("pg_restore-{tool_version}"),
    }
}

/// A temp root that removes itself — `t.TempDir`.
pub(crate) struct TempRoot(pub(crate) PathBuf);

impl TempRoot {
    pub(crate) fn new(group: &str) -> Result<Self, String> {
        let root = std::env::temp_dir().join(format!("c06-s34-{group}-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&root).map_err(|e| format!("create the protected root: {e}"))?;
        // The broker expects to create the broker root itself underneath.
        Ok(Self(root))
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One broker composition: the production [`Service`] (for the ticket
/// readback surface) plus a second [`RecoveryJournalStore`] over the same
/// protected root — `c06NewBrokerService`'s `(service, root)` pair, with the
/// second store standing where upstream's second `broker.Service` stands.
pub(crate) struct Broker {
    pub(crate) service: Service,
    pub(crate) journal: Arc<RecoveryJournalStore>,
    pub(crate) root: PathBuf,
    _tmp: TempRoot,
}

pub(crate) fn broker_battery(group: &str) -> Result<Broker, String> {
    let tmp = TempRoot::new(group)?;
    let root = tmp.0.join(format!("protected-{group}"));
    let service = Service::new(root.clone(), rustix::process::getuid().as_raw())
        .map_err(|e| format!("compose the broker service for group {group}: {e}"))?;
    let signing = Arc::new(
        SigningService::new_persistent(&root)
            .map_err(|e| format!("compose the signing service for group {group}: {e}"))?,
    );
    let journal = Arc::new(
        RecoveryJournalStore::new(&root, signing, ProtectedFileBackend::new(root.clone()))
            .map_err(|e| format!("compose the second journal for group {group}: {e}"))?,
    );
    Ok(Broker {
        service,
        journal,
        root,
        _tmp: tmp,
    })
}

// ---------------------------------------------------------------------------
// The protected-record walk — `c06WalkProtectedRecords` and the two writers.
// Records are identified by CONTENT, never by directory or filename, exactly
// as upstream; the guards (exactly one match, expected previous state) are
// what keep a vacuous find from turning into a vacuous pair.
// ---------------------------------------------------------------------------

pub(crate) fn walk_protected_records(
    root: &Path,
    visit: &mut dyn FnMut(&Path, &serde_json::Value),
) -> Result<usize, String> {
    let mut seen = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| format!("walk the protected root {}: {e}", dir.display()))?
        {
            let path = entry
                .map_err(|e| format!("walk {}: {e}", dir.display()))?
                .path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let payload = std::fs::read(&path)
                .map_err(|e| format!("read the protected record {}: {e}", path.display()))?;
            if let Ok(record) = serde_json::from_slice::<serde_json::Value>(&payload) {
                seen += 1;
                visit(&path, &record);
            }
        }
    }
    if seen == 0 {
        return Err(format!(
            "the protected root {} holds no JSON records at all; every search over it would report \"not found\" for a reason that has nothing to do with what was searched for",
            root.display()
        ));
    }
    Ok(seen)
}

/// `c06SetProtectedTicketRecordState` — rewrite exactly the `state` member
/// of the protected ticket record for `ticket_id`, preserving every other
/// member; returns the state it replaced.
/// Wire records carry Go's PascalCase member names (`TicketID`); read both
/// shapes so the walk stays layout-independent but never silently misses.
pub(crate) fn member<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    snake: &str,
    pascal: &str,
) -> Option<&'a serde_json::Value> {
    object.get(snake).or_else(|| object.get(pascal))
}

fn set_protected_ticket_record_state(
    root: &Path,
    ticket_id: Uuid,
    state: &str,
) -> Result<String, String> {
    let wanted = ticket_id.to_string();
    let mut found: Option<(PathBuf, serde_json::Map<String, serde_json::Value>, String)> = None;
    let mut count = 0usize;
    walk_protected_records(root, &mut |path, record| {
        let Some(object) = record.as_object() else {
            return;
        };
        let Some(ticket) = member(object, "ticket", "Ticket").and_then(|t| t.as_object()) else {
            return;
        };
        let Some(state_value) = member(object, "state", "State").and_then(|s| s.as_str()) else {
            return;
        };
        if member(ticket, "ticket_id", "TicketID").and_then(|t| t.as_str()) != Some(wanted.as_str())
        {
            return;
        }
        count += 1;
        let mut rewritten = object.clone();
        // Rewrite the member under the key it already carries.
        let key = if object.contains_key("State") {
            "State"
        } else {
            "state"
        };
        rewritten.insert(key.to_owned(), serde_json::Value::String(state.to_owned()));
        found = Some((path.to_path_buf(), rewritten, state_value.to_owned()));
    })?;
    if count != 1 {
        return Err(format!(
            "{count} protected records carry ticket {ticket_id}, want exactly 1; a pair stated over a record this suite could not find, or could not tell from another, is a pair about nothing"
        ));
    }
    let (path, rewritten, previous) = found.expect("count == 1");
    let encoded = serde_json::to_vec(&serde_json::Value::Object(rewritten))
        .map_err(|e| format!("re-encode the protected ticket record: {e}"))?;
    // In place, so the mode, owner and link count the reader validates are
    // the ones the journal itself created.
    std::fs::write(&path, encoded).map_err(|e| {
        format!(
            "rewrite the protected ticket record {}: {e}",
            path.display()
        )
    })?;
    Ok(previous)
}

/// `c06RemoveProtectedRestoreOperationRecord` — remove the protected record
/// of one restore operation. The Rust record is identified by shape: a
/// top-level `operation_id` matching the target AND the `phase` /
/// `last_checkpoint` members only an operation record carries (upstream's
/// `Validate()` discriminator), with the journal's own `read` re-checked
/// around the removal so a wrong pick can never pass silently.
fn remove_protected_operation_record(
    journal: &RecoveryJournalStore,
    root: &Path,
    operation_id: Uuid,
) -> Result<(), String> {
    let wanted = operation_id.to_string();
    let mut found: Vec<PathBuf> = Vec::new();
    walk_protected_records(root, &mut |path, record| {
        let Some(object) = record.as_object() else {
            return;
        };
        if member(object, "operation_id", "OperationID").and_then(|o| o.as_str())
            != Some(wanted.as_str())
        {
            return;
        }
        if member(object, "phase", "Phase").is_none()
            || member(object, "last_checkpoint", "LastCheckpoint").is_none()
        {
            return;
        }
        found.push(path.to_path_buf());
    })?;
    if found.len() != 1 {
        return Err(format!(
            "{} protected records are the restore operation {operation_id}, want exactly 1; the pair below would otherwise be stated over a journal in a state this suite did not construct",
            found.len()
        ));
    }
    if journal.read(operation_id).is_err() {
        return Err(format!(
            "the journal cannot read operation {operation_id} before its record is removed; removing the file below would then be attributed to a record that was never the one the journal reads"
        ));
    }
    std::fs::remove_file(&found[0]).map_err(|e| {
        format!(
            "remove the protected operation record {}: {e}",
            found[0].display()
        )
    })?;
    if journal.read(operation_id).is_ok() {
        return Err(format!(
            "the journal still reads operation {operation_id} after its record was removed; the file removed was not the record the journal reads"
        ));
    }
    Ok(())
}

/// `c06TicketsIdentical` — used ONLY to establish that an alteration
/// altered something and that the read-back record is whole; it never
/// decides whether the journal should have admitted a ticket.
fn tickets_identical(left: &RestoreTicket, right: &RestoreTicket) -> bool {
    left == right
}

fn flip_last_hex_digit(value: &str) -> String {
    if value.is_empty() {
        return "0".to_owned();
    }
    let (head, last) = value.split_at(value.len() - 1);
    let replacement = if last == "0" { "1" } else { "0" };
    format!("{head}{replacement}")
}

// ---------------------------------------------------------------------------
// Scenario 3 — the verify handler battery and the live-operation resolver.
// ---------------------------------------------------------------------------

/// A `RestoreVerifyRunner` that answers a fixed outcome — the reachability
/// harness's launcher half: whether a verify was attempted and what it
/// returned are the observable the battery reasons about.
struct FixedVerifyRunner {
    outcome: Result<RestoreVerifyReceipt, Failure>,
    calls: Arc<Mutex<usize>>,
}

impl central_adapter_linux::helper::restore::RestoreVerifyRunner for FixedVerifyRunner {
    fn run_restore_verify(&self, _deadline: Instant) -> Result<RestoreVerifyReceipt, Failure> {
        *self.calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.outcome.clone()
    }
}

fn verify_request() -> RestoreVerifyRequest {
    RestoreVerifyRequest {
        operation_id: Uuid::now_v7().to_string(),
    }
}

/// `newRestoreReachabilityHarness`'s inner half: the destructive handler
/// that records what the resolver forwards to it. One value satisfies all
/// three ports, exactly as the production `Arc<ResolvingRestoreOperationHandler>`
/// does upstream.
struct RecordingInner {
    calls: Mutex<usize>,
    saw_operation: Mutex<String>,
}

impl RecordingInner {
    fn new() -> Self {
        Self {
            calls: Mutex::new(0),
            saw_operation: Mutex::new(String::new()),
        }
    }

    fn note(&self, operation_id: &str) -> Response {
        *self.calls.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        *self.saw_operation.lock().unwrap_or_else(|e| e.into_inner()) = operation_id.to_owned();
        Response::new(operation_id, "success", 0, "")
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn saw(&self) -> String {
        self.saw_operation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl RestoreApplyHandler for RecordingInner {
    fn authorize_restore_apply(
        &self,
        _deadline: Instant,
        request: RestoreApplyRequest,
        _peer: &PeerIdentity,
    ) -> Response {
        self.note(&request.operation_id)
    }
}

impl RestoreResumeHandler for RecordingInner {
    fn authorize_restore_resume(
        &self,
        _deadline: Instant,
        request: RestoreResumeRequest,
        _peer: &PeerIdentity,
    ) -> Response {
        self.note(&request.operation_id)
    }
}

impl RestoreAbandonHandler for RecordingInner {
    fn authorize_restore_abandon(
        &self,
        _deadline: Instant,
        request: RestoreAbandonRequest,
        _peer: &PeerIdentity,
    ) -> Response {
        self.note(&request.operation_id)
    }
}

/// The live-operation source over the REAL journal — the same
/// `inspect_restore_barrier` the crate-private production source calls.
struct JournalLiveOperations {
    journal: Arc<RecoveryJournalStore>,
}

impl RestoreLiveOperationSource for JournalLiveOperations {
    fn live_restore_operations(
        &self,
        _deadline: Instant,
    ) -> Result<Vec<RestoreOperation>, Failure> {
        let (operation, active) = self.journal.inspect_restore_barrier()?;
        Ok(if active { vec![operation] } else { Vec::new() })
    }
}

/// The live-ticket source over the REAL journal, mirroring
/// `issued_ticket_operation_ids`: every ticket record still in state
/// `issued` and not expired contributes its bound operation identity.
struct JournalLiveTickets {
    root: PathBuf,
}

impl RestoreLiveTicketSource for JournalLiveTickets {
    fn live_restore_ticket_operation_ids(&self, _deadline: Instant) -> Result<Vec<Uuid>, Failure> {
        let mut ids = Vec::new();
        let root = self.root.clone();
        // A root holding no JSON records yet simply has no issued tickets:
        // "there is none" is the measurement, not a read failure.
        if walk_protected_records(&root, &mut |_path, record| {
            let Some(object) = record.as_object() else {
                return;
            };
            if member(object, "state", "State").and_then(|s| s.as_str()) != Some("issued") {
                return;
            }
            let Some(ticket) = member(object, "ticket", "Ticket").and_then(|t| t.as_object())
            else {
                return;
            };
            let expired = member(ticket, "expires_at", "ExpiresAt")
                .and_then(|e| e.as_str())
                .and_then(|e| {
                    OffsetDateTime::parse(e, &time::format_description::well_known::Rfc3339).ok()
                })
                .is_some_and(|expires| expires <= OffsetDateTime::now_utc());
            if expired {
                return;
            }
            if let Some(id) = member(ticket, "operation_id", "OperationID")
                .and_then(|o| o.as_str())
                .and_then(|o| o.parse::<Uuid>().ok())
            {
                ids.push(id);
            }
        })
        .is_ok()
        {
            return Ok(ids);
        }
        Ok(ids)
    }
}

/// `liveRestoreOperationsFake` — the fixed set the two-candidate direction
/// is stated over.
struct FixedLiveOperations(Vec<RestoreOperation>);

impl RestoreLiveOperationSource for FixedLiveOperations {
    fn live_restore_operations(
        &self,
        _deadline: Instant,
    ) -> Result<Vec<RestoreOperation>, Failure> {
        Ok(self.0.clone())
    }
}

struct FixedLiveTickets(Vec<Uuid>);

impl RestoreLiveTicketSource for FixedLiveTickets {
    fn live_restore_ticket_operation_ids(&self, _deadline: Instant) -> Result<Vec<Uuid>, Failure> {
        Ok(self.0.clone())
    }
}

/// Dispatch one verb through the production resolving handler — the
/// in-process half of `dispatchRestore`.
fn dispatch_verb(
    handler: &ResolvingRestoreOperationHandler,
    verb: &str,
    peer: &PeerIdentity,
) -> Response {
    let transport_id = Uuid::now_v7().to_string();
    match verb {
        "apply" => handler.authorize_restore_apply(
            deadline(),
            RestoreApplyRequest {
                operation_id: transport_id,
            },
            peer,
        ),
        "resume" => handler.authorize_restore_resume(
            deadline(),
            RestoreResumeRequest {
                operation_id: transport_id,
            },
            peer,
        ),
        "abandon" => handler.authorize_restore_abandon(
            deadline(),
            RestoreAbandonRequest {
                operation_id: transport_id,
            },
            peer,
        ),
        other => panic!("unknown restore verb {other}"),
    }
}

const RESTORE_OPERATION_VERBS: [&str; 3] = ["apply", "resume", "abandon"];

/// Mint a ticket, issue its apply authorization and really begin the
/// restore — `c06BeginARealRestore`: the barrier the live source reads is
/// occupied by something a restore actually consumed a ticket to create.
pub(crate) fn begin_a_real_restore(
    journal: &RecoveryJournalStore,
    facts: &RestoreAdmissionFacts,
    base: OffsetDateTime,
) -> Result<RestoreOperation, String> {
    let ticket = journal
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("live-operation"),
            facts,
            Uuid::nil(),
            base,
        )
        .map_err(|e| format!("mint the ticket the barrier's live operation is begun from: {e}"))?;
    let authorization = journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            peer().uid,
            peer().pid,
            base + time::Duration::seconds(1),
        )
        .map_err(|e| format!("record the apply authorization: {e}"))?;
    let operation = journal
        .begin(&ticket, &authorization, base + time::Duration::seconds(2))
        .map_err(|e| format!("begin the restore the live source is supposed to see: {e}"))?;
    if operation.is_terminal() {
        return Err(format!(
            "the begun operation is already terminal at phase {:?}, so it would never occupy the barrier",
            operation.phase
        ));
    }
    Ok(operation)
}

/// `c06.s3.restore_verify` — the verify handler battery plus the
/// live-operation cardinality battery over a real protected journal.
#[test]
fn c06_s3_restore_verify() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s3.restore_verify";
    crate::slice_c::scenario(
        id,
        |profile| crate::slice_c::unmet_precondition(id, profile).or_else(missing_live_env),
        |_s| {
            let mut log = ScenarioLog::new(id);
            log.recordf(format_args!("{SCENARIO3_SCOPE_DISCLOSURE}"));
            crate::continuous_run::gate_the_sequence("c06.s2.corruption_detected", &mut log)?;
            run_verify_and_resolver_battery(&mut log, id, &measured_pg_tool_version())
        },
    );
}

/// `c06RunRestoreVerifyBattery` — the verify handler battery plus the
/// live-operation cardinality battery, taken out so the live scenario and
/// the portable entry point run one body.
fn run_verify_and_resolver_battery(
    log: &mut ScenarioLog,
    id: &str,
    tool_version: &str,
) -> Result<(), String> {
    {
        let peer = peer();

        // --- 1. The production seams exist and their shapes are the
        // matrix's rows. Verify's handler is constructed with nothing
        // but a runner — no PAM confirmer, no destructive ceremony
        // type, exactly as upstream's matrix row reads
        // (RequiresPAM=false, Destructive=false); apply, resume and
        // abandon reach the operator only through the
        // ResolvingRestoreOperationHandler the destructive handlers sit
        // behind. The construction is the assertion: a handler built
        // without a confirmer slot cannot be PAM-gated.
        expect3(
            id,
            "the verify seam is implemented as a runner behind the production handler with no PAM-confirmer and no destructive-ceremony parameter, while apply, resume and abandon are the destructive verbs the production resolving handler stands in front of",
        );
        let _verify: RestoreVerifyHandlerImpl =
            RestoreVerifyHandlerImpl::new(Some(Box::new(FixedVerifyRunner {
                outcome: Err(new_restore_refusal(RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP)),
                calls: Arc::new(Mutex::new(0)),
            })));
        let _apply_handler_ty: fn() -> RestoreApplyAuthorizationHandler = unreachable_marker;
        let _resolving: ResolvingRestoreOperationHandler =
            ResolvingRestoreOperationHandler::new(None, None, None, None, None);

        // --- 2. The verify handler's own checks, over its production
        //    body: absent runner -> RESTORE_VERIFY_UNAVAILABLE;
        //    malformed peer -> the same; a runner refusal -> its reason
        //    passes through untouched; an expired receipt -> refused;
        //    a usable one -> the safe projection only.
        expect3(
            id,
            "with no runner the handler defers as RESTORE_VERIFY_UNAVAILABLE, a malformed peer is refused the same way, a runner refusal's reason reaches the operator untouched, an expired receipt is refused, and a usable receipt answers success carrying only the safe projection",
        );
        let absent = RestoreVerifyHandlerImpl::new(None);
        let response = absent.verify_restore(deadline(), verify_request(), &peer);
        if response.reason != "RESTORE_VERIFY_UNAVAILABLE" || response.exit_code == 0 {
            return Err(format!(
                "verify with no runner answered {:?}/{}/{}, want RESTORE_VERIFY_UNAVAILABLE",
                response.outcome, response.exit_code, response.reason
            ));
        }
        let present = RestoreVerifyHandlerImpl::new(Some(Box::new(FixedVerifyRunner {
            outcome: Err(new_restore_refusal(RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP)),
            calls: Arc::new(Mutex::new(0)),
        })));
        let malformed = PeerIdentity {
            uid: peer.uid,
            gid: peer.gid,
            pid: 0,
        };
        let response = present.verify_restore(deadline(), verify_request(), &malformed);
        if response.reason != "RESTORE_VERIFY_UNAVAILABLE" {
            return Err(format!(
                "verify over a malformed peer answered {}, want RESTORE_VERIFY_UNAVAILABLE",
                response.reason
            ));
        }
        for refused in [
            RESTORE_REFUSAL_NO_ADMISSIBLE_BACKUP,
            RESTORE_REFUSAL_BACKUP_CANDIDATE_AMBIGUOUS,
        ] {
            let handler = RestoreVerifyHandlerImpl::new(Some(Box::new(FixedVerifyRunner {
                outcome: Err(new_restore_refusal(refused)),
                calls: Arc::new(Mutex::new(0)),
            })));
            let response = handler.verify_restore(deadline(), verify_request(), &peer);
            if response.reason != refused || response.exit_code == 0 {
                return Err(format!(
                    "verify over a runner refused as {refused} answered {:?}/{}/{}; the admitted refusal vocabulary must reach the operator untouched",
                    response.outcome, response.exit_code, response.reason
                ));
            }
        }
        let backup_id = Uuid::now_v7();
        let expired = RestoreVerifyHandlerImpl::new(Some(Box::new(FixedVerifyRunner {
            outcome: Ok(RestoreVerifyReceipt {
                ticket_id: Uuid::now_v7().to_string(),
                backup_id: backup_id.to_string(),
                expires_at: OffsetDateTime::now_utc() - time::Duration::minutes(1),
            }),
            calls: Arc::new(Mutex::new(0)),
        })));
        let response = expired.verify_restore(deadline(), verify_request(), &peer);
        if response.reason != "RESTORE_VERIFY_FAILED" || response.exit_code == 0 {
            return Err(format!(
                "verify over an expired receipt answered {:?}/{}/{}, want RESTORE_VERIFY_FAILED; an out-of-window ticket is not a verification",
                response.outcome, response.exit_code, response.reason
            ));
        }
        let usable_ticket = Uuid::now_v7();
        let usable = RestoreVerifyHandlerImpl::new(Some(Box::new(FixedVerifyRunner {
            outcome: Ok(RestoreVerifyReceipt {
                ticket_id: usable_ticket.to_string(),
                backup_id: backup_id.to_string(),
                expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(20),
            }),
            calls: Arc::new(Mutex::new(0)),
        })));
        let response = usable.verify_restore(deadline(), verify_request(), &peer);
        if response.exit_code != 0 || response.outcome != "success" {
            return Err(format!(
                "verify over a usable receipt answered {:?}/{}/{}, want success",
                response.outcome, response.exit_code, response.reason
            ));
        }
        let Some(result) = response.result.as_ref() else {
            return Err("a successful verify carries no result projection".to_owned());
        };
        let projected: RestoreVerifyResult = serde_json::from_str(result.get())
            .map_err(|e| format!("decode the verify projection: {e}"))?;
        if projected.backup_id != backup_id.to_string()
            || projected.ticket_id != usable_ticket.to_string()
        {
            return Err(format!(
                "the verify projection names backup {} ticket {}, want {} and {}; a projection naming anything else reports a verify of a different backup",
                projected.backup_id, projected.ticket_id, backup_id, usable_ticket
            ));
        }
        log.recordf(format_args!(
                "verify handler battery: absent runner and malformed peer refuse as RESTORE_VERIFY_UNAVAILABLE, both admitted refusal reasons pass through untouched, the expired receipt is refused, and the usable receipt answers success carrying only the safe projection"
            ));

        // --- 3. Live-operation cardinality over the REAL journal. ----
        let facts = admission_facts(tool_version);
        let broker = broker_battery("live")?;
        let base = OffsetDateTime::now_utc();

        // ZERO, measured: an empty protected root reports nothing live.
        expect3(
            id,
            "with an empty protected root the live-operation source measures ZERO candidates, and apply, resume and abandon each refuse as RESTORE_NO_LIVE_OPERATION while forwarding nothing",
        );
        let inner = RecordingInner::new();
        let zero_handler = ResolvingRestoreOperationHandler::new(
            Some(Box::new(JournalLiveOperations {
                journal: broker.journal.clone(),
            })),
            Some(Box::new(JournalLiveTickets {
                root: broker.root.clone(),
            })),
            Some(Box::new(RecordingInner::new())),
            Some(Box::new(RecordingInner::new())),
            Some(Box::new(RecordingInner::new())),
        );
        let _ = inner; // each cardinality gets a fresh harness, upstream-fashion
        let mut zero_answers = Vec::new();
        for verb in RESTORE_OPERATION_VERBS {
            let response = dispatch_verb(&zero_handler, verb, &peer);
            if response.reason != RESTORE_REFUSAL_NO_LIVE_OPERATION || response.exit_code == 0 {
                return Err(format!(
                    "`restore {verb}` over an empty protected root answered {:?}/{}/{}, want {RESTORE_REFUSAL_NO_LIVE_OPERATION} at a non-zero exit",
                    response.outcome, response.exit_code, response.reason
                ));
            }
            zero_answers.push(response.reason);
        }
        log.recordf(format_args!(
                "live-operation cardinality zero: the real journal's empty barrier measured nothing live and all three verbs answered {RESTORE_REFUSAL_NO_LIVE_OPERATION}"
            ));

        // ONE, measured: a real consumed ticket occupies the barrier.
        expect3(
            id,
            "after a real ticket is minted and really consumed by a begin against the same protected root, resume and abandon resolve exactly that operation and forward it to the destructive handler, while apply -- whose source is issued tickets, now consumed -- refuses",
        );
        let begun = begin_a_real_restore(&broker.journal, &facts, base)?;
        let live = broker
            .journal
            .inspect_restore_barrier()
            .map_err(|e| format!("read the barrier after the begin: {e}"))?;
        if !live.1 || live.0.operation_id != begun.operation_id {
            return Err(format!(
                "the barrier reports active={} operation={} for the restore this run began ({}); a source that cannot see the begun operation makes the resolution below a fact about nothing",
                live.1, live.0.operation_id, begun.operation_id
            ));
        }
        let one_inner = Arc::new(RecordingInner::new());
        let one_handler = ResolvingRestoreOperationHandler::new(
            Some(Box::new(JournalLiveOperations {
                journal: broker.journal.clone(),
            })),
            Some(Box::new(JournalLiveTickets {
                root: broker.root.clone(),
            })),
            Some(Box::new(OneInner {
                inner: one_inner.clone(),
            })),
            Some(Box::new(OneInner {
                inner: one_inner.clone(),
            })),
            Some(Box::new(OneInner {
                inner: one_inner.clone(),
            })),
        );
        for verb in ["resume", "abandon"] {
            let response = dispatch_verb(&one_handler, verb, &peer);
            if response.reason == RESTORE_REFUSAL_NO_LIVE_OPERATION
                || response.reason == RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS
            {
                return Err(format!(
                    "`restore {verb}` over a barrier holding exactly the begun operation was refused as {}; the resolver fired where it had exactly one candidate",
                    response.reason
                ));
            }
        }
        // apply resolves over ISSUED tickets; the consumed one is gone.
        let response = dispatch_verb(&one_handler, "apply", &peer);
        if response.reason != RESTORE_REFUSAL_NO_LIVE_OPERATION {
            return Err(format!(
                "`restore apply` over a barrier whose only ticket was consumed answered {:?}/{}, want {RESTORE_REFUSAL_NO_LIVE_OPERATION}: apply's source is issued tickets and the consumed one must not still resolve",
                response.outcome, response.reason
            ));
        }
        if one_inner.calls() != 2 {
            return Err(format!(
                "the destructive handler was reached {} times behind the resolved resume/abandon pair; the resolver forwarded nothing or the wrong count",
                one_inner.calls()
            ));
        }
        if one_inner.saw() != begun.operation_id.to_string() {
            return Err(format!(
                "the destructive handler acted on operation {}, want the protected operation the barrier holds ({}); a verb that acts on anything other than what it resolved has not resolved anything",
                one_inner.saw(),
                begun.operation_id
            ));
        }
        log.recordf(format_args!(
                "live-operation cardinality one: the real journal reported exactly the begun operation, resume and abandon reached the destructive handler against that protected identity, and apply refused because its ticket was consumed"
            ));

        // TWO, at the resolver, over a fixed set — the real barrier's
        // single occupancy makes this direction unreachable below the
        // resolver, exactly as upstream states.
        expect3(
            id,
            "with TWO live operations the verbs refuse as RESTORE_LIVE_OPERATION_AMBIGUOUS, forward nothing, and name neither operation in the refusal reason -- refusing to guess is not the same as refusing while still nominating a candidate",
        );
        let first = live_operation_fixture(&begun)?;
        let second = live_operation_fixture(&begun)?;
        if first.operation_id == second.operation_id {
            return Err("the two fixture operations carry one identity".to_owned());
        }
        let two_inner = Arc::new(RecordingInner::new());
        let two_handler = ResolvingRestoreOperationHandler::new(
            Some(Box::new(FixedLiveOperations(vec![
                first.clone(),
                second.clone(),
            ]))),
            Some(Box::new(FixedLiveTickets(vec![
                Uuid::now_v7(),
                Uuid::now_v7(),
            ]))),
            Some(Box::new(OneInner {
                inner: two_inner.clone(),
            })),
            Some(Box::new(OneInner {
                inner: two_inner.clone(),
            })),
            Some(Box::new(OneInner {
                inner: two_inner.clone(),
            })),
        );
        for verb in RESTORE_OPERATION_VERBS {
            let response = dispatch_verb(&two_handler, verb, &peer);
            if response.reason != RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS
                || response.exit_code == 0
            {
                return Err(format!(
                    "`restore {verb}` over two live operations answered {:?}/{}/{}, want {RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS} at a non-zero exit",
                    response.outcome, response.exit_code, response.reason
                ));
            }
            for candidate in [&first, &second] {
                if response
                    .reason
                    .contains(&candidate.operation_id.to_string())
                {
                    return Err(format!(
                        "the ambiguous `restore {verb}` refusal names operation {}; the rule is to refuse and NOT choose, and a refusal that still nominates a candidate is a choice with a disclaimer",
                        candidate.operation_id
                    ));
                }
            }
        }
        if two_inner.calls() != 0 {
            return Err(format!(
                "the destructive handler was reached {} times behind an ambiguous resolution; the resolver chose one of two protected restores",
                two_inner.calls()
            ));
        }
        // The three cardinalities answer three mutually distinct
        // reasons at the operator's terminal.
        for verb in RESTORE_OPERATION_VERBS {
            let zero = dispatch_verb(&zero_handler, verb, &peer);
            let two = dispatch_verb(&two_handler, verb, &peer);
            if zero.reason == two.reason {
                return Err(format!(
                    "`restore {verb}` answers {} for both an empty barrier and an ambiguous one; an operator cannot tell \"there is nothing in flight\" from \"I will not choose\"",
                    zero.reason
                ));
            }
        }
        log.recordf(format_args!(
                "live-operation cardinality two: all three verbs answered {RESTORE_REFUSAL_LIVE_OPERATION_AMBIGUOUS}, forwarded nothing, named neither candidate, and the zero/one/two cardinalities answer mutually distinct reasons"
            ));
        Ok(())
    }
}

/// Marker proving the apply handler type (the destructive half the resolver
/// fronts) exists in this composition — assigned to a fn pointer so the
/// assertion is structural rather than a comment.
fn unreachable_marker() -> RestoreApplyAuthorizationHandler {
    unreachable!("never called")
}

/// `OneInner` — hands the shared [`RecordingInner`] to all three verb
/// slots; `Arc` would do this in production.
struct OneInner {
    inner: Arc<RecordingInner>,
}

impl RestoreApplyHandler for OneInner {
    fn authorize_restore_apply(
        &self,
        deadline: Instant,
        request: RestoreApplyRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.inner.authorize_restore_apply(deadline, request, peer)
    }
}

impl RestoreResumeHandler for OneInner {
    fn authorize_restore_resume(
        &self,
        deadline: Instant,
        request: RestoreResumeRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.inner.authorize_restore_resume(deadline, request, peer)
    }
}

impl RestoreAbandonHandler for OneInner {
    fn authorize_restore_abandon(
        &self,
        deadline: Instant,
        request: RestoreAbandonRequest,
        peer: &PeerIdentity,
    ) -> Response {
        self.inner
            .authorize_restore_abandon(deadline, request, peer)
    }
}

/// `liveRestoreOperationFixture` — a well-formed, non-terminal operation
/// distinct from any other fixture: the begun operation's own shape with a
/// fresh identity, so the resolver's validation admits it.
fn live_operation_fixture(begun: &RestoreOperation) -> Result<RestoreOperation, String> {
    let mut fixture = begun.clone();
    fixture.operation_id = Uuid::now_v7();
    fixture.ticket_id = Uuid::now_v7();
    if fixture.validate().is_err() || fixture.is_terminal() {
        return Err("the fixture operation does not validate as non-terminal".to_owned());
    }
    Ok(fixture)
}

/// The pg_restore version this host carries — measured, never asserted from
/// a constant, because manifest field 17 checks a run's tool versions
/// against the ticket's recorded ones.
pub(crate) fn measured_pg_tool_version() -> String {
    crate::fixture::pg_tool_version_output("pg_restore")
        .and_then(|raw| crate::evidence::parse_pg_tool_version("pg_restore", &raw))
        .unwrap_or_else(|_| "16.14".to_owned())
}

// ---------------------------------------------------------------------------
// Scenario 4 — the ticket is recorded, and it is one-use.
// ---------------------------------------------------------------------------

/// The mismatch plan — governance's negative list for this scenario is
/// replay, expiry, signature/hash mismatch and target mismatch; replay and
/// expiry have their own steps and these five alterations are the rest.
struct TicketMutation {
    name: &'static str,
    class: &'static str,
    apply: fn(&RestoreTicket) -> RestoreTicket,
    /// Declared, not derived: the two signature-class halves are told
    /// apart by nothing else.
    changes_canonical_payload: bool,
}

const MISMATCH_SIGNATURE: &str = "signature";
const MISMATCH_HASH: &str = "hash";
const MISMATCH_TARGET: &str = "target";

fn mutation_plan() -> Vec<TicketMutation> {
    vec![
        TicketMutation {
            name: "the ticket's signature was altered while every signed field was left alone",
            class: MISMATCH_SIGNATURE,
            apply: |ticket| {
                let mut t = ticket.clone();
                t.hmac = flip_last_hex_digit(&t.hmac);
                t
            },
            changes_canonical_payload: false,
        },
        TicketMutation {
            name: "the ticket's hidden nonce was altered, which is a signed field the operator never sees",
            class: MISMATCH_SIGNATURE,
            apply: |ticket| {
                let mut t = ticket.clone();
                let last = t.hidden_nonce.len() - 1;
                t.hidden_nonce[last] ^= 0xFF;
                t
            },
            changes_canonical_payload: true,
        },
        TicketMutation {
            name: "the ticket's sealed manifest digest was altered",
            class: MISMATCH_HASH,
            apply: |ticket| {
                let mut t = ticket.clone();
                t.manifest_digest =
                    synthetic_manifest_digest("a-manifest-this-ticket-was-not-bound-to");
                t
            },
            changes_canonical_payload: true,
        },
        TicketMutation {
            name: "the ticket's target database was altered",
            class: MISMATCH_TARGET,
            apply: |ticket| {
                let mut t = ticket.clone();
                t.target.database.push_str("-somewhere-else");
                t
            },
            changes_canonical_payload: true,
        },
        TicketMutation {
            name: "the ticket's target fingerprint was altered",
            class: MISMATCH_TARGET,
            apply: |ticket| {
                let mut t = ticket.clone();
                t.target_fingerprint =
                    synthetic_manifest_digest("a-target-this-ticket-was-not-bound-to");
                t
            },
            changes_canonical_payload: true,
        },
    ]
}

/// `c06.s4.restore_ticket_one_use` — the ticket is recorded in protected
/// state, is one-use, and its replay, expiry and mismatch negatives are
/// each refused beside an admitted neighbour.
#[test]
fn c06_s4_restore_ticket_one_use() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s4.restore_ticket_one_use";
    crate::slice_c::scenario(
        id,
        |profile| crate::slice_c::unmet_precondition(id, profile).or_else(missing_live_env),
        |_s| {
            let mut log = ScenarioLog::new(id);
            log.recordf(format_args!("{SCENARIO4_SCOPE_DISCLOSURE}"));
            crate::continuous_run::gate_the_sequence("c06.s3.restore_verify", &mut log)?;
            let tool_version = measured_pg_tool_version();
            run_ticket_recorded_and_one_use(&mut log, id, &admission_facts(&tool_version))?;
            let facts = admission_facts(&tool_version);
            let peer = peer();
            let base = OffsetDateTime::now_utc();

            // --- 6. Signature, hash and target mismatch, beside pristine.
            run_mismatch_pairs(&mut log, id, &facts, &peer, base)?;

            // --- 7. Expiry, as two pairs over one ticket. ---------------
            run_expiry_pairs(&mut log, id, &facts, &peer, base)?;

            // --- 8. The two checks steps 4 and 5 lean on, alone. --------
            run_defence_in_depth_pairs(&mut log, id, &facts, &peer, base)?;
            Ok(())
        },
    );
}

/// `c06RunRestoreTicketBattery`'s steps 1-5 — issuance is a judgement, the
/// ticket is recorded whole, the authorization binds the resolved ticket,
/// the begin is admitted, replay is refused beside the admitted resume, and
/// the barrier holds the begun operation. Taken out so the live scenario
/// and the portable entry point run one body.
fn run_ticket_recorded_and_one_use(
    log: &mut ScenarioLog,
    id: &str,
    facts: &RestoreAdmissionFacts,
) -> Result<(), String> {
    let peer = peer();
    // Wall time: one broker read takes its own now() from the wall clock,
    // as upstream documents.
    let base = OffsetDateTime::now_utc();
    {
        // --- 1. Issuance is a judgement, in both directions. --------
        expect4(
            id,
            "the journal refuses to mint a ticket from admission facts carrying a tool version that is not the pinned one, and refuses one carrying an unprefixed capacity evidence digest, and admits the same facts with both put right",
        );
        let recording = broker_battery("recording")?;
        let mut off_version = facts.clone();
        off_version.tool_version = "pg_restore-0.0".to_owned();
        if recording
            .journal
            .issue(
                Uuid::now_v7(),
                &synthetic_manifest_digest("off-version"),
                &off_version,
                Uuid::nil(),
                base,
            )
            .is_ok()
        {
            return Err(
                    "the journal minted a ticket from facts naming an unpinned restore tool; manifest field 17 compares a run's tool versions against the ticket's recorded ones, and a ticket that records whatever it was handed makes that check vacuous"
                        .to_owned(),
                );
        }
        let mut off_digest = facts.clone();
        off_digest.capacity_evidence_digest = facts
            .capacity_evidence_digest
            .trim_start_matches("sha256:")
            .to_owned();
        if recording
            .journal
            .issue(
                Uuid::now_v7(),
                &synthetic_manifest_digest("off-digest"),
                &off_digest,
                Uuid::nil(),
                base,
            )
            .is_ok()
        {
            return Err(
                    "the journal minted a ticket from facts carrying an unprefixed capacity evidence digest"
                        .to_owned(),
                );
        }

        // --- 2. The ticket is recorded, whole, in protected state. --
        expect4(
            id,
            "the ticket the journal mints is recorded in protected state and reads back WHOLE -- every field including the signature and the hidden nonce -- because the admission that consumes it compares whole values",
        );
        let backup_id = Uuid::now_v7();
        let manifest_digest = synthetic_manifest_digest("recording");
        let ticket = recording
                .journal
                .issue(backup_id, &manifest_digest, facts, Uuid::nil(), base)
                .map_err(|e| {
                    format!("the journal refused to mint a ticket from the facts it had just accepted the shape of: {e}")
                })?;
        if ticket.hmac.is_empty() || ticket.hidden_nonce.is_empty() {
            return Err(format!(
                "the minted ticket carries hmac={} nonce={}; a ticket carrying neither is not an authorization, it is a struct",
                !ticket.hmac.is_empty(),
                !ticket.hidden_nonce.is_empty()
            ));
        }
        if ticket.backup_id != backup_id || ticket.manifest_digest != manifest_digest {
            return Err(format!(
                "the minted ticket names backup {} at manifest {:?}, want {backup_id} at {manifest_digest:?}",
                ticket.backup_id, ticket.manifest_digest
            ));
        }
        if ticket.tool_version != facts.tool_version {
            return Err(format!(
                "the minted ticket records tool version {:?}; this battery was driven at {:?} and manifest field 17 compares a run's tool versions against exactly this field",
                ticket.tool_version, facts.tool_version
            ));
        }
        if ticket.capacity_evidence_digest != facts.capacity_evidence_digest {
            return Err(format!(
                "the minted ticket records capacity evidence digest {:?}, want {:?}",
                ticket.capacity_evidence_digest, facts.capacity_evidence_digest
            ));
        }
        let read_back = recording
                .service
                .read_issued_restore_ticket_for_operation(ticket.operation_id)
                .map_err(|e| {
                    format!("the broker could not read back the ticket it had just recorded, from the operation identity alone: {e}")
                })?;
        if !tickets_identical(&read_back, &ticket) {
            return Err(
                    "the ticket read back from protected state is not field-for-field the ticket that was minted; the admission that consumes it compares whole values, so a record that differs anywhere can never be spent"
                        .to_owned(),
                );
        }
        log.recordf(format_args!(
                "ticket recorded: signature and hidden nonce present, tool version {:?} matches the version this battery was driven at, capacity evidence digest carried from the admission facts, and the record reads back whole from the operation identity alone",
                ticket.tool_version
            ));

        expect4(
            id,
            "the broker resolves the ticket from the operation identity alone when exactly one issued ticket matches, and refuses for an operation identity no ticket was ever minted against",
        );
        if recording
            .service
            .read_issued_restore_ticket_for_operation(Uuid::now_v7())
            .is_ok()
        {
            return Err(
                    "the broker resolved a ticket for an operation identity nothing was ever issued against"
                        .to_owned(),
                );
        }

        // --- 3. The apply authorization, and the one-use consumption.
        expect4(
            id,
            "an apply authorization issued from the operation identity alone binds the ticket the journal resolved for itself, and beginning the restore with that pair is ADMITTED -- this is the neighbour every refusal below is measured against",
        );
        let authorization = recording
                .journal
                .issue_restore_apply_authorization_for_operation(
                    ticket.operation_id,
                    peer.uid,
                    peer.pid,
                    base + time::Duration::seconds(1),
                )
                .map_err(|e| {
                    format!("the journal refused to record an apply authorization for the operation it had just issued a ticket for: {e}")
                })?;
        if !authorization.binds(&ticket) {
            return Err(format!(
                "the apply authorization names ticket {} for operation {}; the journal was asked only for the operation and must have resolved the ticket itself",
                authorization.ticket_id, authorization.operation_id
            ));
        }
        let operation = recording
                .journal
                .begin(&ticket, &authorization, base + time::Duration::seconds(2))
                .map_err(|e| {
                    format!("the journal refused to begin a restore from a freshly minted ticket and its own freshly issued authorization ({e}); every refusal below this line would then be indistinguishable from a journal that refuses everything")
                })?;
        if operation.ticket_id != ticket.ticket_id || operation.operation_id != ticket.operation_id
        {
            return Err(format!(
                "the begun operation names ticket {} and operation {}, want {} and {}",
                operation.ticket_id, operation.operation_id, ticket.ticket_id, ticket.operation_id
            ));
        }
        if operation.last_checkpoint != RestoreCheckpoint::TicketConsumed
            || operation.phase != RestorePhase::Applying
        {
            return Err(format!(
                "the begun operation is at phase {:?} checkpoint {:?}, want applying at ticket_consumed; the durable record of the ticket having been spent IS that checkpoint",
                operation.phase, operation.last_checkpoint
            ));
        }
        if operation.capacity_evidence_digest != ticket.capacity_evidence_digest {
            return Err(format!(
                "the begun operation carries capacity evidence digest {:?} where its ticket recorded {:?}",
                operation.capacity_evidence_digest, ticket.capacity_evidence_digest
            ));
        }
        log.recordf(format_args!(
                "one-use, first use: the restore began at phase {:?} checkpoint {:?}, carrying the ticket's own capacity evidence digest",
                operation.phase, operation.last_checkpoint
            ));

        // --- 4. Replay, refused, beside the admitted neighbour. -----
        expect4(
            id,
            "replaying the SAME ticket and the SAME authorization that were admitted a moment ago is refused -- over-determined, because the barrier, the spent authorization and the existing operation record each refuse it independently -- and a second apply authorization for the same operation is refused too, so a consumed ticket cannot buy a second destructive run",
        );
        if recording
            .journal
            .begin(&ticket, &authorization, base + time::Duration::seconds(3))
            .is_ok()
        {
            return Err(
                    "the journal began a second restore from a ticket it had already consumed; the same authorization that was spent once was accepted again"
                        .to_owned(),
                );
        }
        if recording
            .journal
            .issue_restore_apply_authorization_for_operation(
                ticket.operation_id,
                peer.uid,
                peer.pid,
                base + time::Duration::seconds(3),
            )
            .is_ok()
        {
            return Err(
                    "the journal issued a fresh apply authorization for an operation whose ticket was already consumed; the operator would then be able to begin a second destructive run rather than being directed to resume"
                        .to_owned(),
                );
        }
        if recording
            .service
            .read_issued_restore_ticket(ticket.ticket_id)
            .is_ok()
        {
            return Err("the consumed ticket still resolves as issued".to_owned());
        }

        // --- 5. The disentangler: the ticket is CONSUMED, not gone. -
        expect4(
            id,
            "the same journal, at the same moment, still ADMITS the resume path -- which reads the ticket record and requires it to be present and consumed and to name this operation -- so the apply refusals above are because the ticket was consumed and not because the journal stopped answering or the record went missing",
        );
        let resume_authorization = recording
                .journal
                .issue_restore_resume_authorization_for_operation(
                    ticket.operation_id,
                    peer.uid,
                    peer.pid,
                    base + time::Duration::seconds(4),
                )
                .map_err(|e| {
                    format!("the journal refused a resume authorization for the operation it had just begun ({e}). That path requires the ticket record to be present and in the consumed state, so its refusal here leaves the apply refusals above unattributed")
                })?;
        if resume_authorization.ticket_id != ticket.ticket_id {
            return Err(format!(
                "the resume authorization names ticket {}, want the consumed ticket {}",
                resume_authorization.ticket_id, ticket.ticket_id
            ));
        }
        let resumed = recording
                .journal
                .resume(
                    ticket.operation_id,
                    &resume_authorization,
                    base + time::Duration::seconds(5),
                )
                .map_err(|e| {
                    format!("the journal refused to resume the operation it had just authorized a resume for: {e}")
                })?;
        if resumed.operation_id != operation.operation_id || resumed.ticket_id != ticket.ticket_id {
            return Err(format!(
                "the resumed operation is {} on ticket {}, want {} on {}",
                resumed.operation_id, resumed.ticket_id, operation.operation_id, ticket.ticket_id
            ));
        }
        let (barrier, active) = recording
            .journal
            .inspect_restore_barrier()
            .map_err(|e| format!("inspect the restore barrier: {e}"))?;
        if !active || barrier.operation_id != operation.operation_id {
            return Err(format!(
                "the restore barrier reports active={active} operation={}; the begun operation must occupy it, and a barrier that does not hold it is a restore this host would let something else start alongside",
                barrier.operation_id
            ));
        }
        log.recordf(format_args!(
                "one-use, second use: apply refused twice and the ticket no longer resolves as issued, while resume -- which requires the ticket record present and consumed -- was ADMITTED and the barrier holds the begun operation; the ticket was spent, not lost"
            ));
        Ok(())
    }
}

/// `c06RunRestoreTicketMismatchPairs` — every alteration refused FIRST and
/// the pristine ticket admitted LAST, in one journal at one clock, with one
/// authorization.
fn run_mismatch_pairs(
    log: &mut ScenarioLog,
    id: &str,
    facts: &RestoreAdmissionFacts,
    peer: &PeerIdentity,
    base: OffsetDateTime,
) -> Result<(), String> {
    expect4(
        id,
        "each altered ticket is refused at the same moment the pristine ticket, with the same authorization, is admitted -- so each refusal is attributable to the one field that was altered and to nothing else",
    );
    let broker = broker_battery("mismatch")?;
    let ticket = broker
        .journal
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("mismatch"),
            facts,
            Uuid::nil(),
            base,
        )
        .map_err(|e| format!("mint the ticket the mismatch pairs are stated over: {e}"))?;
    let authorization = broker
        .journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            peer.uid,
            peer.pid,
            base + time::Duration::seconds(1),
        )
        .map_err(|e| {
            format!("record the apply authorization the mismatch pairs are stated over: {e}")
        })?;
    let at = base + time::Duration::seconds(2);

    let mut covered = [0usize; 3];
    let classes = [MISMATCH_SIGNATURE, MISMATCH_HASH, MISMATCH_TARGET];
    for mutation in mutation_plan() {
        let altered = (mutation.apply)(&ticket);
        // Non-vacuity, before the refusal is trusted.
        if tickets_identical(&altered, &ticket) {
            return Err(format!(
                "{} produced a ticket identical to the pristine one, so the refusal below would be over the ticket the admitted half presents",
                mutation.name
            ));
        }
        let changed = altered.canonical_payload() != ticket.canonical_payload();
        if changed != mutation.changes_canonical_payload {
            return Err(format!(
                "{} declares that it {} the signed payload and it {}; the two halves of the signature class are told apart by nothing else",
                mutation.name,
                if mutation.changes_canonical_payload {
                    "changes"
                } else {
                    "leaves alone"
                },
                if changed { "changes" } else { "leaves alone" }
            ));
        }
        let index = classes.iter().position(|c| *c == mutation.class).unwrap();
        covered[index] += 1;
        if broker.journal.begin(&altered, &authorization, at).is_ok() {
            return Err(format!(
                "the journal began a restore from a ticket where {}; the presented ticket is not the recorded one, and admitting it would let a caller substitute what the restore acts on",
                mutation.name
            ));
        }
    }
    for (index, class) in classes.iter().enumerate() {
        if covered[index] == 0 {
            return Err(format!(
                "no mismatch in this plan is of class {class}; governance's negative list names signature/hash mismatch AND target mismatch, and a plan missing one of them carries out half of it"
            ));
        }
    }
    let begun = broker
        .journal
        .begin(&ticket, &authorization, at)
        .map_err(|e| {
            format!("the journal refused the pristine ticket at the same moment, with the same authorization, that it refused every altered one ({e}). Every mismatch refusal above is then unattributed: they are equally explained by a journal that refuses everything")
        })?;
    if begun.ticket_id != ticket.ticket_id
        || begun.manifest_digest != ticket.manifest_digest
        || begun.target != ticket.target
    {
        return Err(format!(
            "the admitted operation names ticket {} at manifest {:?} on a different target, want {} at {:?} on the ticket's own",
            begun.ticket_id, begun.manifest_digest, ticket.ticket_id, ticket.manifest_digest
        ));
    }
    log.recordf(format_args!(
        "mismatch pairs: 5 alterations across 3 classes were each refused, and the pristine ticket was admitted with the same authorization at the same moment"
    ));
    Ok(())
}

/// `c06RunRestoreTicketExpiryPairs` — two pairs over one ticket, both
/// moving only the clock.
fn run_expiry_pairs(
    log: &mut ScenarioLog,
    id: &str,
    facts: &RestoreAdmissionFacts,
    peer: &PeerIdentity,
    base: OffsetDateTime,
) -> Result<(), String> {
    expect4(
        id,
        "the same ticket admits an apply authorization INSIDE its window and refuses one PAST it, and beginning a restore with the same ticket and the same authorization is REFUSED past the ticket's expiry -- where the authorization is still valid -- and ADMITTED inside it",
    );
    let broker = broker_battery("expiry")?;
    let ticket = broker
        .journal
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("expiry"),
            facts,
            Uuid::nil(),
            base,
        )
        .map_err(|e| format!("mint the ticket the expiry pairs are stated over: {e}"))?;
    let lifetime = ticket.expires_at - ticket.issued_at;
    if lifetime <= time::Duration::ZERO {
        return Err(format!(
            "the minted ticket's lifetime is {lifetime}; a ticket with no window has no expiry to make a pair out of"
        ));
    }
    let inside = ticket.issued_at + time::Duration::seconds(1);
    let past = ticket.expires_at + time::Duration::seconds(1);

    if broker
        .journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            peer.uid,
            peer.pid,
            inside,
        )
        .is_err()
    {
        return Err(
            "the journal refused an apply authorization inside the ticket's own window; the refusal past it would then say nothing about expiry"
                .to_owned(),
        );
    }
    if broker
        .journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            peer.uid,
            peer.pid,
            past,
        )
        .is_ok()
    {
        return Err(
            "the journal issued an apply authorization for a ticket that had already expired"
                .to_owned(),
        );
    }

    // PAIR B. Minted close to the ticket's expiry so it outlives the
    // ticket — that is what lets the refusal be attributed.
    let late_enough = ticket.expires_at - time::Duration::seconds(10);
    let authorization = broker
        .journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            peer.uid,
            peer.pid,
            late_enough,
        )
        .map_err(|e| {
            format!(
                "the journal refused an apply authorization still inside the ticket's window: {e}"
            )
        })?;
    if !authorization.valid_at(past) {
        return Err(format!(
            "the apply authorization is itself invalid at the moment this pair refuses (issued {}, expires {}, moment {past}); the refusal below could then be the authorization's expiry rather than the ticket's",
            authorization.issued_at, authorization.expires_at
        ));
    }
    if !ticket.is_expired_at(past) {
        return Err(format!(
            "the ticket is not expired at {past}, so the refused half of this pair is not a statement about expiry at all"
        ));
    }
    let almost = ticket.expires_at - time::Duration::seconds(1);
    if ticket.is_expired_at(almost) || !authorization.valid_at(almost) {
        return Err(format!(
            "the admitted half of this pair is not admissible on the domain's own predicates (ticket expired={}, authorization valid={} at {almost}); the pair's two halves would then differ in more than the clock",
            ticket.is_expired_at(almost),
            authorization.valid_at(almost)
        ));
    }
    if broker.journal.begin(&ticket, &authorization, past).is_ok() {
        return Err(
            "the journal began a restore from a ticket that had already expired".to_owned(),
        );
    }
    let begun = broker
        .journal
        .begin(&ticket, &authorization, almost)
        .map_err(|e| {
            format!("the journal refused the SAME ticket and the SAME authorization at a moment inside the ticket's window ({e}); the refusal past the window is then not attributable to expiry, because this pair's admitted half does not hold")
        })?;
    if begun.ticket_id != ticket.ticket_id {
        return Err(format!(
            "the admitted half of the expiry pair began operation {} on ticket {}, want ticket {}",
            begun.operation_id, begun.ticket_id, ticket.ticket_id
        ));
    }
    log.recordf(format_args!(
        "expiry pairs: over a ticket whose window is {lifetime}, an authorization was admitted inside it and refused past it, and the same ticket-and-authorization pair was refused past the window and admitted inside it with the authorization provably still valid at the refused moment"
    ));
    Ok(())
}

/// `c06RunRestoreTicketDefenceInDepthPairs` — the two checks the one-use
/// argument rests on, made to carry the refusal ON THEIR OWN: the resume
/// path's requirement on the ticket's state, and begin's requirement on it,
/// each with the admitted neighbour taken from the same journal at the same
/// moment.
fn run_defence_in_depth_pairs(
    log: &mut ScenarioLog,
    id: &str,
    facts: &RestoreAdmissionFacts,
    peer: &PeerIdentity,
    base: OffsetDateTime,
) -> Result<(), String> {
    expect4(
        id,
        "a resume authorization is ADMITTED while the ticket record is present and consumed, is REFUSED when that record's state alone is put back to issued, and is ADMITTED again when it is put back; and with the operation record removed, beginning from the CONSUMED ticket with a real unspent authorization that binds it is REFUSED while a never-consumed ticket still begins -- so each check refuses on its own where nothing else can",
    );
    let broker = broker_battery("defence")?;
    let ticket = broker
        .journal
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("defence"),
            facts,
            Uuid::nil(),
            base,
        )
        .map_err(|e| format!("mint the ticket the defence-in-depth pairs are stated over: {e}"))?;
    let authorization = broker
        .journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            peer.uid,
            peer.pid,
            base + time::Duration::seconds(1),
        )
        .map_err(|e| {
            format!("record the apply authorization the defence pairs are stated over: {e}")
        })?;
    let operation = broker
        .journal
        .begin(&ticket, &authorization, base + time::Duration::seconds(2))
        .map_err(|e| {
            format!("begin the restore the defence pairs are stated over ({e}); every refusal below would then be indistinguishable from a journal that refuses everything")
        })?;

    // PAIR A: the resume path's requirement on the ticket's state.
    if broker
        .journal
        .issue_restore_resume_authorization_for_operation(
            operation.operation_id,
            peer.uid,
            peer.pid,
            base + time::Duration::seconds(3),
        )
        .is_err()
    {
        return Err(
            "the journal refused a resume authorization for the operation it had just begun, with the ticket record present and consumed; the refusal this pair is about would then say nothing"
                .to_owned(),
        );
    }
    let previous = set_protected_ticket_record_state(&broker.root, ticket.ticket_id, "issued")?;
    if previous != "consumed" {
        return Err(format!(
            "the ticket record was in state {previous:?} after its restore had begun, want consumed; the durable record of the ticket having been spent is not where this pair reads it"
        ));
    }
    if broker
        .journal
        .issue_restore_resume_authorization_for_operation(
            operation.operation_id,
            peer.uid,
            peer.pid,
            base + time::Duration::seconds(4),
        )
        .is_ok()
    {
        return Err(
            "the journal issued a resume authorization for an operation whose ticket record says it was never consumed. Resume authority is anchored on the consumed ticket -- that is what makes an admitted resume evidence the ticket really was spent"
                .to_owned(),
        );
    }
    let restored = set_protected_ticket_record_state(&broker.root, ticket.ticket_id, "consumed")?;
    if restored != "issued" {
        return Err(format!(
            "the ticket record was in state {restored:?} rather than the issued this pair had put it in"
        ));
    }
    let resume_authorization = broker
        .journal
        .issue_restore_resume_authorization_for_operation(
            operation.operation_id,
            peer.uid,
            peer.pid,
            base + time::Duration::seconds(5),
        )
        .map_err(|e| {
            format!("the journal refused a resume authorization after the ticket record's state was put back to consumed ({e}); the refusal above is then not attributable to that state, because this pair's second admitted half does not hold")
        })?;
    log.recordf(format_args!(
        "defence pair A: with the ticket record consumed a resume authorization was admitted, with that one field moved to issued it was refused, and with it put back it was admitted again"
    ));

    // PAIR B: begin's requirement on the ticket's state, alone. The resume
    // authorization minted above is real, unspent, and binds this ticket.
    if !resume_authorization.binds(&ticket) {
        return Err(format!(
            "the authorization this pair presents binds ticket {} for operation {} rather than the consumed ticket {}; begin would refuse it before reading any record",
            resume_authorization.ticket_id, resume_authorization.operation_id, ticket.ticket_id
        ));
    }
    if !resume_authorization.valid_at(base + time::Duration::seconds(6)) {
        return Err(
            "the authorization this pair presents is not valid at the moment the pair refuses; begin would refuse it on its own lifetime and the pair would prove nothing about the ticket"
                .to_owned(),
        );
    }
    remove_protected_operation_record(&broker.journal, &broker.root, operation.operation_id)?;
    let (_, still_active) = broker
        .journal
        .inspect_restore_barrier()
        .map_err(|e| format!("inspect the barrier with the operation record removed: {e}"))?;
    if still_active {
        return Err(
            "the restore barrier still reports active with the operation record removed; the barrier would then be what refuses below, and this pair would be a second statement of the over-determined refusal"
                .to_owned(),
        );
    }
    if broker
        .journal
        .begin(
            &ticket,
            &resume_authorization,
            base + time::Duration::seconds(6),
        )
        .is_ok()
    {
        return Err(
            "the journal began a restore from a ticket its own protected record says was already consumed, once the operation record that ALSO would have refused was out of the way. A journal that has been repaired or tampered with is exactly the case the ticket's state is read for"
                .to_owned(),
        );
    }
    // The control in the other direction, in the same root at the same
    // moment: a ticket that was never consumed still begins.
    let fresh = broker
        .journal
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("defence-control"),
            facts,
            Uuid::nil(),
            base + time::Duration::seconds(6),
        )
        .map_err(|e| format!("mint the never-consumed control ticket: {e}"))?;
    let fresh_authorization = broker
        .journal
        .issue_restore_apply_authorization_for_operation(
            fresh.operation_id,
            peer.uid,
            peer.pid,
            base + time::Duration::seconds(7),
        )
        .map_err(|e| format!("record the control's apply authorization: {e}"))?;
    let control = broker
        .journal
        .begin(&fresh, &fresh_authorization, base + time::Duration::seconds(8))
        .map_err(|e| {
            format!("the journal refused a never-consumed ticket in the same root at the same moment ({e}); the refusal of the consumed one above is then not attributable to its state, because this control does not hold")
        })?;
    if control.ticket_id != fresh.ticket_id {
        return Err(format!(
            "the control operation names ticket {}, want the never-consumed {}",
            control.ticket_id, fresh.ticket_id
        ));
    }
    log.recordf(format_args!(
        "defence pair B: with the operation record removed and the barrier clear, the consumed ticket was refused a second begin while a never-consumed ticket was admitted in the same root at the same moment"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// The portable half — `TestC06TheRestoreTicketBatteryHoldsAgainstARealBroker`'s
// position. The journal needs no root and no container; a workstation need not
// carry the pinned pg_restore, so this entry is driven at the pinned literal —
// the ONE input a workstation genuinely cannot measure, exactly as upstream
// states. It records no outcome against any catalogue entry.
// ---------------------------------------------------------------------------

/// `TestC06TheRestoreVerifyResolutionBatteryHoldsAgainstTheRealOperatorSurface`'s
/// position: scenario 3's battery runs on any workstation — every component
/// it judges (the handler seams, the protected journal, the resolver) needs
/// nothing a reference host has. Driven at the pinned literal for the one
/// input a workstation cannot measure; records no catalogue outcome.
#[test]
fn c06_s34_portable_verify_resolution_battery() {
    let id = "c06.s3.restore_verify";
    let mut log = ScenarioLog::new(id);
    log.recordf(format_args!("{SCENARIO3_SCOPE_DISCLOSURE}"));
    run_verify_and_resolver_battery(&mut log, id, "16.14").unwrap();
}

#[test]
fn c06_s34_portable_ticket_battery() {
    let id = "c06.s4.restore_ticket_one_use";
    let mut log = ScenarioLog::new(id);
    log.recordf(format_args!("{SCENARIO4_SCOPE_DISCLOSURE}"));
    let facts = admission_facts("16.14");
    run_ticket_recorded_and_one_use(&mut log, id, &facts).unwrap();
    let peer = peer();
    let base = OffsetDateTime::now_utc();
    run_mismatch_pairs(&mut log, id, &facts, &peer, base).unwrap();
    run_expiry_pairs(&mut log, id, &facts, &peer, base).unwrap();
    run_defence_in_depth_pairs(&mut log, id, &facts, &peer, base).unwrap();
}
