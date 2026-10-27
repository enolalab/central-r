//! Port of upstream `cmd/central/c06_continuous_run_test.go` — the nine
//! restart injections (`c06.r1`–`c06.r9`), the restart-observation composer,
//! and the sequence gate between catalogue entries.
//!
//! In this port the continuous run IS the armed test process: the ten
//! scenarios and the nine injections each record exactly one outcome through
//! `slice_c::scenario`, and `zz_emit` reconciles the whole catalogue after
//! the last entry — one bring-up, nineteen outcomes, in order, shared
//! `RecordSet`, exactly as `TestC06TheContinuousRecoverySequence` drives it.
//! The injections depend on nothing the scenarios left behind (each is over
//! its own protected root), which is the same independence upstream states.

use std::path::Path;
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use central_adapter_linux::broker::protected_file::ProtectedFileBackend;
use central_adapter_linux::broker::recovery_journal::RecoveryJournalStore;
use central_adapter_linux::broker::server::Service;
use central_adapter_linux::broker::signing::SigningService;
use central_backup::backup::operation::{
    BACKUP_CHECKSUM_MANIFEST, BACKUP_DATABASE_SCHEMA_VERSION, BACKUP_DUMP_TOOL_VERSION,
    BACKUP_INVENTORY_BOUNDARY, BACKUP_SERVICE_IDENTITY, BACKUP_TARGET_LOCK_PROTOCOL,
    BackupAcceptedFacts, BackupPhase, new_backup_operation,
};
use central_backup::domain::TargetIdentity;
use central_backup::port::RestoreJournalStore as _;
use central_backup::recovery::operation::{
    RestoreCheckpoint, RestoreOperation, RestorePhase, RestoreTicket,
};
use central_foundation::failure::FailureKind;

use crate::evidence;
use crate::fixture::{self, JournalWalk};
use crate::runner::runner;
use crate::scenario2::{self, ScenarioLog};
use crate::scenario5::{PINNED_PG_TOOL_VERSION, synthetic_authority_reset_receipt};
use crate::scenario34::{TempRoot, admission_facts, peer, synthetic_manifest_digest};
use crate::slice_c;

// ---------------------------------------------------------------------------
// The scope disclosure — `c06RestartScopeDisclosure`, verbatim.
// ---------------------------------------------------------------------------

/// `c06RestartScopeDisclosure` — carried on every divergence any restart
/// injection emits.
pub(crate) const RESTART_SCOPE_DISCLOSURE: &str = "SCOPE, CARRIED ON EVERY DIVERGENCE A RESTART INJECTION EMITS: what is proven here is DURABILITY ACROSS A RESTART. The state at each boundary is written through the domain's own closed transition methods and the broker's own compare-and-swap, so a boundary that is reached at all was reached along a legal edge; the restart is then a FRESH broker composed over the SAME protected root, and every reading and every refusal afterwards is made by a process that never saw the record written. NOTHING IS RELAXED to do it: no permission check, ceremony, peer predicate, record signature or transition rule is substituted or weakened anywhere, and the fresh broker is composed through the same constructor and argument shape the root restore engine uses. WHAT IS NOT SATISFIED, in every entry. The DAEMON is not restarted: its memory locking, dump suppression, system-call filter, capability drop and activated listener are not exercised, because no systemd unit for the broker exists in this repository and a packaged restart is not something this harness can perform or verify -- this is scenario 4's declared boundary and it is unchanged. No boundary here was reached from a real sealed backup: no backup can be sealed on any host while the production composition supplies no throughput gate, and an acceptance suite must not supply one. The restore boundaries are begun from a RECORDED apply authorization and not from a PERFORMED operator ceremony, which is scenario 4's disclosed shortcut and is STILL OPEN -- a recorded authorization is not a performed ceremony, nothing in these entries establishes one, and each entry states that again in its own observed_after_restart so the reader of a PASSING artifact is told as plainly as the reader of a failing one. The pre-restore session, grant and lease census is a relation, so it is decided only where a real database exists and is named not_established everywhere else rather than assumed.";

/// `c06RestartExpect` — the only way a restart injection states an
/// expectation: the disclosure is attached through every route out of every
/// step, and a convention nothing enforces lasts until the next hurried
/// step is added.
fn restart_expect(id: &str, what: impl AsRef<str>) {
    runner().attach_divergence(
        id,
        &format!("{RESTART_SCOPE_DISCLOSURE} -- {}", what.as_ref()),
    );
}

// ---------------------------------------------------------------------------
// The five assertions, the three verdicts, the carry-forward labels.
// ---------------------------------------------------------------------------

/// `c06RestartAssertionKeys` — the declared set, in emitted order. Four are
/// the Slice C plan's; the fifth is SC-G3's own addition. Answered as a
/// closed set because an assertion absent from a sentence reads like one
/// that held.
pub(crate) const RESTART_ASSERTION_KEYS: [&str; 5] = [
    "no_partial_serve",
    "no_ticket_replay",
    "no_duplicate_seal",
    "no_artifact_delivery_from_quarantine",
    "no_surviving_pre_restore_authority",
];

/// The three verdicts — `held` and `not_established` are deliberately
/// different words for different things (a run that could not decide a
/// property must not read as one that decided it favourably), and
/// `not_applicable` — the property has no subject at this boundary at all —
/// is never a substitute for the second.
pub(crate) const ASSERTION_HELD: &str = "held";
pub(crate) const ASSERTION_NOT_APPLICABLE: &str = "not_applicable";
pub(crate) const ASSERTION_NOT_ESTABLISHED: &str = "not_established";

/// `c06RestartVerdicts`.
pub(crate) const RESTART_VERDICTS: [&str; 3] = [
    ASSERTION_HELD,
    ASSERTION_NOT_APPLICABLE,
    ASSERTION_NOT_ESTABLISHED,
];

/// `c06CarryForwardMarker` — fixed opening of every carry-forward label, so
/// the recorder can REQUIRE the label rather than trusting a convention.
pub(crate) const CARRY_FORWARD_MARKER: &str = "CARRY-FORWARD, NOT CLOSED:";

/// `c06RecordedAuthorizationCarryForward` — the label every restore-side
/// boundary carries; verbatim upstream.
pub(crate) const RECORDED_AUTHORIZATION_CARRY_FORWARD: &str = "CARRY-FORWARD, NOT CLOSED: the restore state this boundary was reached in was begun from an apply authorization RECORDED directly against the broker, not from a ceremony PERFORMED on a physical console. A recorded authorization is not a performed ceremony and nothing in this entry establishes one. It could not be closed here and no fallback was added for it: closing it needs a live restore operation in the INSTALLED instance for the operator surface to resolve, which needs a sealed backup, which no host can produce while the production composition supplies no throughput gate. WHERE THIS LABEL DOES AND DOES NOT REACH A READER: through the restart injections only. RestartInjectionRecord emits observed_after_restart on a PASS, while ScenarioRecord drops its divergence unless the outcome failed and the ten scenarios carry no equivalent free-text field -- so scenario 4, whose disclosed shortcut this is, does not state its own carry-forward in its own record anywhere in this document, and a reader takes it from the injections that carry it here.";

/// `c06SyntheticBackupCarryForward` — the label every backup-side boundary
/// carries; a different gap with the same root cause.
pub(crate) const SYNTHETIC_BACKUP_CARRY_FORWARD: &str = "CARRY-FORWARD, NOT CLOSED: the backup state this boundary was reached in was written into the protected journal through the domain's own transitions, not produced by a real backup create. No backup can be sealed on any host while the production composition supplies no throughput gate, and an acceptance suite must not supply one. What is evidenced is the journal's behaviour across a restart, never a backup that was taken.";

/// `c06RestartedProcess` — what these injections restart, named for what it
/// is rather than flattering it: NOT a process restart. A fresh broker is
/// composed over the same protected root INSIDE THIS PROCESS — no fork, no
/// exec, no new PID — which establishes journal durability across a restart
/// and nothing about the daemon's memory locking, dump suppression, filter,
/// capability drop or activated listener. Read from the emitter's own
/// vocabulary so a value it stops admitting fails at the recorder.
const RESTARTED_PROCESS: &str = evidence::RESTART_PROCESS_BROKER_SERVICE_RECOMPOSED_IN_PROCESS;

// ---------------------------------------------------------------------------
// The observation composer — `c06ComposeRestartObservation`.
// ---------------------------------------------------------------------------

/// `c06RestartAssertion` — one of the five properties, with the verdict
/// this entry reached and the reason a reader needs for it.
pub(crate) struct RestartAssertion {
    pub key: &'static str,
    pub verdict: &'static str,
    pub because: String,
}

/// `c06Assertion` — the constructor every call site uses, so the field
/// order can never be transposed at a call site the way a bare literal's
/// can.
fn assertion(
    key: &'static str,
    verdict: &'static str,
    because: impl Into<String>,
) -> RestartAssertion {
    RestartAssertion {
        key,
        verdict,
        because: because.into(),
    }
}

/// `c06ComposeRestartObservation` — the text governance field 23 carries
/// for one boundary: the state the restarted process found, every one of
/// the five assertions with verdict and reason, and the carry-forward
/// label. It returns Err rather than failing, so every rule can be
/// exercised portably over fabricated inputs.
pub(crate) fn compose_restart_observation(
    state: &str,
    assertions: &[RestartAssertion],
    carry_forward: &str,
) -> Result<String, String> {
    let mut problems: Vec<String> = Vec::new();
    if state.trim().is_empty() {
        problems.push(
            "the observation names no post-restart state; governance field 23 carries the phase and checkpoint the restarted process found, and an entry with none reports a restart it observed nothing after"
                .to_owned(),
        );
    }
    let mut seen: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for a in assertions {
        *seen.entry(a.key).or_insert(0) += 1;
        if !RESTART_VERDICTS.contains(&a.verdict) {
            problems.push(format!(
                "{} carries verdict {:?}, which is outside {RESTART_VERDICTS:?}; a verdict nothing recognises reads as an assertion that was made",
                a.key, a.verdict
            ));
        }
        if a.because.trim().is_empty() {
            problems.push(format!(
                "{} carries verdict {:?} with no reason; a bare verdict tells a reader what this run concluded and nothing at all about what it did",
                a.key, a.verdict
            ));
        }
    }
    for key in RESTART_ASSERTION_KEYS {
        match seen.get(key).copied().unwrap_or(0) {
            1 => {}
            0 => problems.push(format!(
                "{key} is never answered; the four properties the Slice C plan names and SC-G3's own fifth are answered as a closed set precisely so that an absent one cannot read like one that held"
            )),
            n => problems.push(format!(
                "{key} is answered {n} times, so which answer reached the artifact depends on the order they were composed in"
            )),
        }
    }
    for key in seen.keys() {
        if !RESTART_ASSERTION_KEYS.contains(key) {
            problems.push(format!(
                "{key} is not one of the five declared post-restart assertions"
            ));
        }
    }
    if !carry_forward.trim_start().starts_with(CARRY_FORWARD_MARKER) {
        problems.push(format!(
            "the observation carries no label opening {CARRY_FORWARD_MARKER:?}. Field 23's free text is the ONLY place in the ratified artifact shape where a still-open carry-forward reaches a reader of a PASSING entry -- the runner drops divergences unless the outcome failed -- so an entry that does not state one there states it nowhere a reader can reach"
        ));
    }
    if !problems.is_empty() {
        problems.sort();
        return Err(format!(
            "this restart observation cannot be recorded:\n  - {}",
            problems.join("\n  - ")
        ));
    }

    let mut rendered = Vec::with_capacity(assertions.len() + 2);
    rendered.push(state.trim().to_owned());
    for key in RESTART_ASSERTION_KEYS {
        for a in assertions {
            if a.key == key {
                rendered.push(format!("{}={} ({})", a.key, a.verdict, a.because.trim()));
            }
        }
    }
    rendered.push(carry_forward.trim().to_owned());
    Ok(rendered.join(" | "))
}

// ---------------------------------------------------------------------------
// The restart itself.
// ---------------------------------------------------------------------------

/// `c06RestartProtectedRoot` — one 0700 directory per injection, inside a
/// temp root the test owns. Upstream's root-owned 0700 directory becomes a
/// process-owned one here: the port composes the broker at this process's
/// own uid (scenario 4's disclosed composition), and 0700 is still the
/// permission the protected root carries.
fn restart_protected_root(id: &str) -> Result<(TempRoot, std::path::PathBuf), String> {
    let tmp = TempRoot::new(id)?;
    let root = tmp.0.join("protected");
    std::fs::create_dir_all(&root)
        .map_err(|e| format!("create the protected root for {id}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("mode the protected root for {id}: {e}"))?;
    }
    Ok((tmp, root))
}

/// `c06RestartTheBroker` — the restart itself: a fresh broker composed over
/// the SAME protected root (`Service::new` plus a fresh
/// `RecoveryJournalStore`, the same pair `broker_battery` composes), so
/// everything it reads afterwards is a record a process that never saw the
/// write made. `new_persistent` constructors re-open an existing root —
/// re-reading is exactly what a restart does. The pair is returned: the
/// journal carries the write/read/CAS surface and the service carries the
/// ticket readback surface (`read_issued_restore_ticket` is a Service
/// method, exactly as upstream reaches it through `*broker.Service`).
fn restart_the_broker(
    root: &Path,
    occasion: &str,
) -> Result<(Service, Arc<RecoveryJournalStore>), String> {
    let service = Service::new(root.to_path_buf(), rustix::process::getuid().as_raw())
        .map_err(|e| format!("compose the broker service {occasion}: {e}"))?;
    let signing = Arc::new(
        SigningService::new_persistent(root)
            .map_err(|e| format!("compose the signing service {occasion}: {e}"))?,
    );
    let journal = Arc::new(
        RecoveryJournalStore::new(root, signing, ProtectedFileBackend::new(root.to_path_buf()))
            .map_err(|e| format!("compose the restarted journal {occasion}: {e}"))?,
    );
    Ok((service, journal))
}

/// `c06RestartSHA256Fingerprint` — a labelled digest for synthetic facts.
fn restart_sha256_fingerprint(label: &str) -> String {
    use sha2::Digest as _;
    format!(
        "sha256:{}",
        crate::hex_lower(sha2::Sha256::digest(
            format!("c06-restart-{label}").as_bytes()
        ))
    )
}

/// `c06BackupPhaseSequence` — the legal walk, fixed by the domain.
fn backup_phase_sequence() -> [BackupPhase; 4] {
    [
        BackupPhase::Admitted,
        BackupPhase::Dumping,
        BackupPhase::Inventory,
        BackupPhase::Sealing,
    ]
}

/// `c06RestartAcceptedFacts` — the trusted facts a backup admission needs.
/// Obviously synthetic and disclosed as such: there is no real admission on
/// any host for these to be read from. They are nevertheless JUDGED —
/// `BackupAcceptedFacts::validate` is the domain's own validator and
/// `BackupOperation::accept` refuses an accepted point that moved
/// backwards.
fn restart_accepted_facts(at: OffsetDateTime) -> BackupAcceptedFacts {
    BackupAcceptedFacts {
        database_time: at.to_offset(time::UtcOffset::UTC),
        target_fingerprint: restart_sha256_fingerprint("target"),
        config_fingerprint: restart_sha256_fingerprint("config"),
        payload_epoch_id: Uuid::now_v7(),
        repository_binding_id: Uuid::now_v7(),
        target_lock_protocol: BACKUP_TARGET_LOCK_PROTOCOL.to_owned(),
        target_lock_proof: restart_sha256_fingerprint("target-lock"),
        inventory_boundary: BACKUP_INVENTORY_BOUNDARY.to_owned(),
        database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.to_owned(),
        tool_version: BACKUP_DUMP_TOOL_VERSION.to_owned(),
        checksum_manifest: BACKUP_CHECKSUM_MANIFEST.to_owned(),
        service_identity: BACKUP_SERVICE_IDENTITY.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// The four backup boundaries (c06.r1 - c06.r4) — `c06RunBackupBoundaryRestart`.
// ---------------------------------------------------------------------------

fn run_backup_boundary_restart(
    id: &str,
    boundary: BackupPhase,
    log: &mut ScenarioLog,
) -> Result<(), String> {
    log.recordf(format_args!("{RESTART_SCOPE_DISCLOSURE}"));

    let (_tmp, root) = restart_protected_root(id)?;
    let (_service, journal) = restart_the_broker(&root, "initial composition of")?;

    let operation_id = Uuid::now_v7();
    let backup_id = Uuid::now_v7();
    let created = OffsetDateTime::now_utc() - time::Duration::minutes(1);

    restart_expect(
        id,
        format!(
            "a planned backup operation is recorded in the protected journal and then carried to the {} boundary through the domain's own transitions and the broker's compare-and-swap",
            boundary.as_str()
        ),
    );
    let planned = new_backup_operation(
        operation_id,
        backup_id,
        TargetIdentity {
            system_id: "c06-restart-target".to_owned(),
            database_oid: "1".to_owned(),
            database: "central".to_owned(),
            config_hash: restart_sha256_fingerprint("config-binding"),
            epoch: 0,
        },
        created,
    )
    .map_err(|e| {
        format!(
            "the domain refused the planned backup operation this boundary is reached from: {e}"
        )
    })?;
    journal
        .create_backup(&planned)
        .map_err(|e| format!("the protected journal refused the planned backup operation this boundary is reached from: {e}"))?;

    let mut current = planned;
    let mut phases = vec![BackupPhase::Planned.as_str().to_owned()];
    let mut at = created;
    let mut tick = move || {
        at += time::Duration::seconds(1);
        at
    };

    // `previous` is the state immediately before the boundary transition —
    // replaying the transition that PRODUCED the boundary is the only
    // replay a restarted controller could actually attempt.
    let mut previous = current.clone();
    for phase in backup_phase_sequence() {
        previous = current.clone();
        let next = if phase == BackupPhase::Admitted {
            current.accept(restart_accepted_facts(tick()))
        } else {
            current.advance(phase, tick())
        }
        .map_err(|e| format!("the domain refused the legal backup transition to {}: {e}. This is the sequence the domain itself fixes, and a domain that will not walk it means every refusal after the restart is a refusal about something else", phase.as_str()))?;
        journal
            .compare_and_swap_backup(&current, &next)
            .map_err(|e| {
                format!(
                    "the protected journal refused the legal backup transition to {}: {e}",
                    phase.as_str()
                )
            })?;
        current = next;
        phases.push(phase.as_str().to_owned());
        if phase == boundary {
            break;
        }
    }
    if current.phase != boundary {
        return Err(format!(
            "the walk stopped at {} and this entry's boundary is {}",
            current.phase.as_str(),
            boundary.as_str()
        ));
    }

    // --- The restart. ----------------------------------------------------
    restart_expect(
        id,
        format!(
            "a broker composed fresh over the same protected root reads the backup operation back at exactly {}, at the same revision, with the accepted facts intact",
            boundary.as_str()
        ),
    );
    let (_fresh_service, fresh) = restart_the_broker(&root, boundary.as_str())?;
    let survived = fresh
        .read_backup_operation(operation_id)
        .map_err(|e| format!("the restarted broker cannot read the backup operation back at the {} boundary: {e}. The evidence did not survive the restart, which is this entry's whole subject", boundary.as_str()))?;
    if survived != current {
        return Err(format!(
            "the restarted broker read the backup operation back as {} at revision {}, and it was left at {} at revision {}; the durable record and what a restarted process sees are not the same record",
            survived.phase.as_str(),
            survived.revision,
            current.phase.as_str(),
            current.revision
        ));
    }

    restart_expect(
        id,
        format!(
            "the restarted broker requires a NEW operation rather than resuming this one: an ordinary backup is resumable only while planned, so at {} it is not resumable",
            boundary.as_str()
        ),
    );
    if survived.phase.is_resumable() {
        return Err(format!(
            "the restarted broker reports the backup at {} as resumable. An ordinary backup is deliberately not resumable past admission -- its consistent point and exclusive ownership can no longer be proven -- and a build in which it is has inverted C01's own rule",
            boundary.as_str()
        ));
    }

    restart_expect(
        id,
        format!(
            "the restarted broker refuses a replay of the very transition that produced the {} boundary, and refuses any transition that would publish a seal",
            boundary.as_str()
        ),
    );
    if fresh.compare_and_swap_backup(&previous, &current).is_ok() {
        return Err(format!(
            "the restarted broker accepted a replay of the transition that produced {}. The compare-and-swap fence is what stops a stale controller from re-performing work the journal already recorded, and without it a restart is a duplicate",
            boundary.as_str()
        ));
    }
    let mut sealed = survived.clone();
    sealed.phase = BackupPhase::Sealed;
    sealed.revision += 1;
    sealed.updated_at = tick();
    if fresh.compare_and_swap_backup(&survived, &sealed).is_ok() {
        return Err(
            "the restarted broker published a seal through compare-and-swap. The journal refuses a transition to sealed outright -- a seal is published only through the attested completion path -- so accepting one means the seal can be published by whatever holds the journal"
                .to_owned(),
        );
    }

    restart_expect(
        id,
        "no restore barrier appears after a backup-boundary restart, so nothing about this boundary half-bars serving",
    );
    let (barrier, present) = fresh
        .inspect_restore_barrier()
        .map_err(|e| format!("the restarted broker cannot answer the serving barrier: {e}"))?;
    if present {
        return Err(format!(
            "a backup boundary left a restore barrier occupied by operation {} at {}; a backup consumes no restore ticket and occupies no restore barrier, so this instance would refuse to serve for a reason no backup created",
            barrier.operation_id,
            barrier.phase.as_str()
        ));
    }

    let observation = compose_restart_observation(
        boundary.as_str(),
        &[
            assertion(
                "no_partial_serve",
                ASSERTION_HELD,
                "the restarted broker reports no restore barrier at all, so nothing this boundary left behind bars or half-bars a serve profile",
            ),
            assertion(
                "no_ticket_replay",
                ASSERTION_NOT_APPLICABLE,
                "a backup boundary consumes no restore ticket, so there is no ticket at this boundary for a restart to replay",
            ),
            assertion(
                "no_duplicate_seal",
                ASSERTION_HELD,
                "the restarted broker refused a replay of the transition that produced this boundary, and refused a compare-and-swap that would publish a seal",
            ),
            assertion(
                "no_artifact_delivery_from_quarantine",
                ASSERTION_NOT_APPLICABLE,
                "no restore operation exists at a backup boundary, so no quarantine exists for a delivery to be attempted from",
            ),
            assertion(
                "no_surviving_pre_restore_authority",
                ASSERTION_NOT_APPLICABLE,
                "a backup performs no authority reset, so this boundary has no pre-restore authority to invalidate; the invalidation census is the authority-reset boundary's subject",
            ),
        ],
        SYNTHETIC_BACKUP_CARRY_FORWARD,
    )?;
    {
        let mut records = fixture::records();
        records.record_restart_observation(id, RESTARTED_PROCESS, &observation)?;
        records.record_journal_walk(JournalWalk {
            operation_id: operation_id.to_string(),
            phases,
            checkpoints: vec![boundary.as_str().to_owned()],
            ticket_issued: 0,
            ticket_consumed: 0,
            boundary: format!("backup:{}", boundary.as_str()),
            state_after_restart: survived.phase.as_str().to_owned(),
        })?;
    }
    log.recordf(format_args!(
        "the backup operation survived a broker restart at {}, at revision {}, not resumable, replay refused",
        survived.phase.as_str(),
        survived.revision
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// The four restore checkpoints (c06.r5 - c06.r8) — `c06RunRestoreCheckpointRestart`.
// ---------------------------------------------------------------------------

/// `c06RestartRestore` — the state one restore-side injection was built
/// over.
struct RestartRestore {
    ticket: RestoreTicket,
    operation: RestoreOperation,
    phases: Vec<String>,
    checkpoints: Vec<String>,
}

/// `c06BeginTheRestartRestore` — mint a ticket, record an apply
/// authorization and begin a restore, returning the whole of what it made.
///
/// IT IS THE THIRD COPY OF THAT SEQUENCE AND THE DUPLICATION IS DELIBERATE:
/// `begin_a_real_restore` and `begin_a_restore_in_the_past` discard the
/// TICKET VALUE, and the ticket value is precisely what the no-ticket-
/// replay assertion after the restart has to present.
///
/// RECORDED, NOT PERFORMED. The authorization below is recorded directly
/// against the broker — scenario 4's disclosed shortcut, still open, and
/// every observation this file records says so in the artifact itself.
fn begin_the_restart_restore(journal: &RecoveryJournalStore) -> Result<RestartRestore, String> {
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(2);
    let ticket = journal
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("restart-injection"),
            &admission_facts(PINNED_PG_TOOL_VERSION),
            Uuid::nil(),
            base,
        )
        .map_err(|e| format!("mint the ticket this injection's restore is begun from: {e}"))?;
    let authorization = journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            peer().uid,
            peer().pid,
            base + time::Duration::seconds(1),
        )
        .map_err(|e| {
            format!("record the apply authorization this injection's restore is begun from: {e}")
        })?;
    let operation = journal
        .begin(&ticket, &authorization, base + time::Duration::seconds(2))
        .map_err(|e| format!("begin the restore this injection restarts: {e}"))?;
    Ok(RestartRestore {
        phases: vec![operation.phase.as_str().to_owned()],
        checkpoints: vec![operation.last_checkpoint.as_str().to_owned()],
        ticket,
        operation,
    })
}

/// `c06CarryTheRestoreToCheckpoint` — walk the operation along the legal
/// sequence until the named checkpoint is the one it stands at, returning
/// the state immediately before the boundary transition. Every transition
/// is produced by the domain's own closed method and every write goes
/// through compare-and-swap, so a walk that completes is itself the
/// assertion that the edge was legal.
// `previous` is reassigned before every transition and read only after the
// last one — the state the boundary was reached FROM. The intermediate
// writes exist so the read always names the pre-transition state of the
// transition that produced the boundary, not the walk's start.
#[allow(unused_assignments)]
fn carry_the_restore_to_checkpoint(
    journal: &RecoveryJournalStore,
    restore: &mut RestartRestore,
    checkpoint: RestoreCheckpoint,
) -> Result<RestoreOperation, String> {
    let mut current = restore.operation.clone();
    let mut at = current.updated_at;
    let mut tick = move || {
        at += time::Duration::seconds(1);
        at
    };
    let mut previous = current.clone();

    macro_rules! advance {
        ($label:expr, $next:expr) => {{
            let next = $next.map_err(|e| {
                format!(
                    "the domain refused the legal restore transition to {}: {e}",
                    $label
                )
            })?;
            journal
                .compare_and_swap_restore(&current, &next)
                .map_err(|e| {
                    format!(
                        "the protected journal refused the legal restore transition to {}: {e}",
                        $label
                    )
                })?;
            previous = current.clone();
            current = next;
            restore.phases.push(current.phase.as_str().to_owned());
            restore
                .checkpoints
                .push(current.last_checkpoint.as_str().to_owned());
        }};
    }

    if current.last_checkpoint != checkpoint {
        let next = current.record_database_replaced(tick());
        advance!("the database-replaced checkpoint", next);
    }
    if current.last_checkpoint != checkpoint {
        let next = current.begin_verification(tick());
        advance!("verification", next);
        let verified = current.record_inventory_verified(tick());
        advance!("the inventory-verified checkpoint", verified);
    }
    if current.last_checkpoint != checkpoint {
        let receipt = synthetic_authority_reset_receipt(&current, tick());
        let next = current.record_authority_reset(&receipt);
        advance!("the authority-reset checkpoint", next);
        let ready = current.mark_ready(tick());
        advance!("the served terminal state", ready);
    }
    if current.last_checkpoint != checkpoint {
        return Err(format!(
            "the walk stopped at {}/{} and this entry's boundary is {}",
            current.phase.as_str(),
            current.last_checkpoint.as_str(),
            checkpoint.as_str()
        ));
    }
    restore.operation = current;
    Ok(previous)
}

/// `c06PartialServeReason` — the no-partial-serve reason for a restore-side
/// boundary, which differs at the terminal one and must say why.
fn partial_serve_reason(terminal: bool) -> &'static str {
    if terminal {
        "the restarted broker considers the operation servable and has released the barrier, which is the design: serving becomes allowed only at the authority-reset checkpoint of a completed operation, so nothing partial is being served"
    } else {
        "the restarted broker finds this operation occupying the serving barrier and does not consider it servable, so an instance that came back here refuses to serve rather than serving from a half-replaced database"
    }
}

/// `c06DuplicateEffectReason` — what actually refused a re-performance at
/// this checkpoint, which is not the same mechanism everywhere.
fn duplicate_effect_reason(replayable: bool) -> &'static str {
    if replayable {
        "the restarted broker refused a replay of the transition that produced this checkpoint, so no effect the journal already recorded can be recorded twice"
    } else {
        "this checkpoint is the one the admission itself created, so it has no earlier state to replay from; what could be re-performed here is the admission, and the restarted broker refused to authorize one for this operation because its ticket no longer stands as issued"
    }
}

fn run_restore_checkpoint_restart(
    id: &str,
    checkpoint: RestoreCheckpoint,
    log: &mut ScenarioLog,
) -> Result<(), String> {
    log.recordf(format_args!("{RESTART_SCOPE_DISCLOSURE}"));

    restart_expect(
        id,
        "a real restore operation is begun through the broker -- ticket issued, apply authorization recorded, begin admitted -- and then carried to this entry's checkpoint through the domain's own transitions",
    );
    let (_tmp, root) = restart_protected_root(id)?;
    let (_service, journal) = restart_the_broker(&root, "initial composition of")?;
    let mut restore = begin_the_restart_restore(&journal)?;
    let previous = carry_the_restore_to_checkpoint(&journal, &mut restore, checkpoint)?;
    let boundary_state = restore.operation.clone();

    // --- The restart. ----------------------------------------------------
    restart_expect(
        id,
        format!(
            "a broker composed fresh over the same protected root reads the restore operation back at exactly the {} checkpoint, at the same revision",
            checkpoint.as_str()
        ),
    );
    let (fresh_service, fresh) = restart_the_broker(&root, checkpoint.as_str())?;
    let survived = fresh
        .read(boundary_state.operation_id)
        .map_err(|e| format!("the restarted broker cannot read the restore operation back at the {} checkpoint: {e}. The evidence did not survive the restart, which is this entry's whole subject", checkpoint.as_str()))?;
    if survived != boundary_state {
        return Err(format!(
            "the restarted broker read the operation back at {}/{} revision {}, and it was left at {}/{} revision {}",
            survived.phase.as_str(),
            survived.last_checkpoint.as_str(),
            survived.revision,
            boundary_state.phase.as_str(),
            boundary_state.last_checkpoint.as_str(),
            boundary_state.revision
        ));
    }

    let state = format!(
        "{}/{}",
        survived.phase.as_str(),
        survived.last_checkpoint.as_str()
    );
    let served = survived.serving_allowed();
    let terminal = checkpoint == RestoreCheckpoint::AuthorityReset;

    restart_expect(
        id,
        format!(
            "the restarted broker's serving barrier answers for {state} exactly as the design requires: a non-terminal operation occupies it and forbids serving, and only the completed one releases it"
        ),
    );
    let (barrier, present) = fresh
        .inspect_restore_barrier()
        .map_err(|e| format!("the restarted broker cannot answer the serving barrier: {e}"))?;
    match (terminal, present) {
        (true, true) => {
            return Err(format!(
                "the completed operation still occupies the serving barrier after the restart (it reports {} at {}); a served operation releases it, and one that does not blocks every later restore forever",
                barrier.operation_id,
                barrier.phase.as_str()
            ));
        }
        (true, false) if !served => {
            return Err(format!(
                "the operation reached {state} and the restarted broker does not consider it servable; the whole point of the authority-reset checkpoint is that serving becomes allowed only there"
            ));
        }
        (false, false) => {
            return Err(format!(
                "the restarted broker reports no restore barrier at {state}. An incomplete restore MUST occupy it: this is the state in which a serve would be a partial serve, and an instance that does not know it is mid-restore will serve from a half-replaced database"
            ));
        }
        (false, true) if served => {
            return Err(format!(
                "the restarted broker considers the operation at {state} servable. No phase permits Central to serve until Ready with the authority reset recorded"
            ));
        }
        (false, true) if barrier.operation_id != survived.operation_id => {
            return Err(format!(
                "the restarted broker's barrier names operation {} and this entry's operation is {}",
                barrier.operation_id, survived.operation_id
            ));
        }
        _ => {}
    }

    // THE REFUSAL THIS ENTRY NAMES: not a Begin against a zero
    // authorization (upstream's note — its first guard fails before ticket
    // state is read), but the issuer itself: a fresh apply authorization
    // for this operation cannot be obtained, because the journal
    // authorizes only an operation's still-ISSUED ticket and this one's
    // was consumed by its own admission.
    restart_expect(
        id,
        "the restarted broker will not authorize a second apply for this operation, because the ticket that admitted it no longer stands as issued in the protected journal",
    );
    if fresh
        .issue_restore_apply_authorization_for_operation(
            survived.operation_id,
            peer().uid,
            peer().pid,
            OffsetDateTime::now_utc(),
        )
        .is_ok()
    {
        return Err(
            "the restarted broker authorized a second apply for an operation whose ticket was consumed before the restart. A restart that resolves a consumed ticket again is a restart that resets the one-use rule"
                .to_owned(),
        );
    }
    if fresh_service
        .read_issued_restore_ticket(restore.ticket.ticket_id)
        .is_ok()
    {
        return Err(
            "the restarted broker still returns the ticket as ISSUED after it was consumed; the refusal above cannot then be attributed to the ticket having been consumed"
                .to_owned(),
        );
    }
    if fresh.read(survived.operation_id).is_err() {
        return Err(
            "the restarted broker no longer answers for the operation the ticket admitted, so the two refusals above are a journal that stopped answering rather than the one-use rule"
                .to_owned(),
        );
    }

    // The control: the SAME restarted broker authorizes an apply for an
    // operation whose ticket IS still issued — a broker that refused
    // everything would satisfy the assertion above and establish nothing.
    restart_expect(
        id,
        "the same restarted broker DOES authorize an apply for an operation whose ticket still stands as issued, so the refusal above is the consumed ticket and not an issuer that refuses everything",
    );
    let control = fresh
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("restart-injection-control"),
            &admission_facts(PINNED_PG_TOOL_VERSION),
            Uuid::nil(),
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| format!("the restarted broker cannot mint a ticket at all ({e}), so the control below cannot be made"))?;
    if fresh
        .issue_restore_apply_authorization_for_operation(
            control.operation_id,
            peer().uid,
            peer().pid,
            OffsetDateTime::now_utc(),
        )
        .is_err()
    {
        return Err(
            "the restarted broker refused to authorize an apply for an operation whose ticket is still ISSUED; the refusal above is then an issuer that refuses everything and says nothing about the consumed ticket"
                .to_owned(),
        );
    }

    // THE REPLAY CHECK IS SKIPPED WHERE IT WOULD PASS FOR THE WRONG REASON.
    // At the ticket-consumed checkpoint `previous` IS the boundary state —
    // a compare-and-swap of a record onto itself is refused by the
    // revision rule, not by the fence. The replay that can happen there is
    // the ticket replay, asserted above.
    let replayable = previous != boundary_state;
    if replayable {
        restart_expect(
            id,
            format!(
                "the restarted broker refuses a replay of the very transition that produced the {} checkpoint",
                checkpoint.as_str()
            ),
        );
        if fresh
            .compare_and_swap_restore(&previous, &boundary_state)
            .is_ok()
        {
            return Err(format!(
                "the restarted broker accepted a replay of the transition that produced {}; the compare-and-swap fence is what stops a stale controller re-performing work the journal already recorded",
                checkpoint.as_str()
            ));
        }
    }

    // The pre-restore authority census is a set of relations, so only a
    // real database can decide it, and only after the reset has actually
    // run.
    let authority_verdict = ASSERTION_NOT_ESTABLISHED;
    let authority_because = if terminal {
        "the reset carried on this operation's own receipt is shaped by the suite rather than performed by the C05 producer, so the seven invalidation counts are the authority-reset SCENARIO's measurement and not this entry's; what this entry establishes is that the checkpoint and its receipt survived the restart"
    } else {
        "this boundary performs no authority reset, so there is no invalidation for a restarted process to observe; what IS established is that serving is barred at this boundary, so no session, grant or lease can be established from the instance while it stands here"
    };

    let observation = compose_restart_observation(
        &state,
        &[
            assertion(
                "no_partial_serve",
                ASSERTION_HELD,
                partial_serve_reason(terminal),
            ),
            assertion(
                "no_ticket_replay",
                ASSERTION_HELD,
                "the restarted broker refused to authorize a second apply for this operation -- a refusal it makes by reading protected ticket state, since the only ticket it will authorize for an operation is a still-ISSUED one and this operation's was consumed by the admission -- and it no longer returns that ticket as issued, while it DID authorize an apply for an operation whose ticket still stands issued and still answers for the operation this one admitted. So the refusal is the ticket's one-use rule, not a dead issuer and not a journal that stopped answering",
            ),
            assertion(
                "no_duplicate_seal",
                ASSERTION_HELD,
                duplicate_effect_reason(replayable),
            ),
            assertion(
                "no_artifact_delivery_from_quarantine",
                ASSERTION_NOT_ESTABLISHED,
                "no delivery was attempted from a quarantined operation; what is established is where the gate sits -- the serve barrier is proven at startup ahead of readiness and ahead of every component, so on a barred instance no delivery path is ever exposed. That is an argument from the gate's position and not a delivery this entry attempted",
            ),
            assertion(
                "no_surviving_pre_restore_authority",
                authority_verdict,
                authority_because,
            ),
        ],
        RECORDED_AUTHORIZATION_CARRY_FORWARD,
    )?;
    {
        let mut records = fixture::records();
        records.record_restart_observation(id, RESTARTED_PROCESS, &observation)?;
        records.record_journal_walk(JournalWalk {
            operation_id: survived.operation_id.to_string(),
            phases: restore.phases.clone(),
            checkpoints: restore.checkpoints.clone(),
            // Two issued, one consumed: this operation's ticket, and the
            // control ticket the one-use assertion needs a live issuer to
            // answer for. The control is minted and never begun from.
            ticket_issued: 2,
            ticket_consumed: 1,
            boundary: checkpoint.as_str().to_owned(),
            state_after_restart: state.clone(),
        })?;
    }
    log.recordf(format_args!(
        "the restore operation survived a broker restart at {state}, at revision {}, ticket refused on replay",
        survived.revision
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Abandonment (c06.r9), ADR 0016 — `c06RestartAfterAbandonment`.
// ---------------------------------------------------------------------------

/// ABANDONMENT IS AN INJECTION AND NOT A SCENARIO: the transition is
/// irreversible, so the claim is about what a process that comes BACK to
/// the journal can do — and the answer must be neither resume nor serve,
/// forever. The phrase discipline below establishes what the helper
/// applies; it does NOT establish that a ceremony was performed, and none
/// is recorded or claimed.
fn restart_after_abandonment(id: &str, log: &mut ScenarioLog) -> Result<(), String> {
    log.recordf(format_args!("{RESTART_SCOPE_DISCLOSURE}"));

    restart_expect(
        id,
        "a real restore operation is begun through the broker and stands in a resumable phase, which is the only kind abandonment is reachable from",
    );
    let (_tmp, root) = restart_protected_root(id)?;
    let (_service, journal) = restart_the_broker(&root, "initial composition of")?;
    let mut restore = begin_the_restart_restore(&journal)?;
    if !restore.operation.is_resumable() {
        return Err(format!(
            "the operation stands at {}, which is not resumable; abandonment is reachable only from a resumable phase, so this entry would be refused for a reason that is not its subject",
            restore.operation.phase.as_str()
        ));
    }

    restart_expect(
        id,
        "the abandonment phrase scoped to this operation satisfies the helper's own confirmation comparison, and the apply phrase at the identical scope does not",
    );
    let instance = restore.operation.operation_id.to_string();
    let target = restore.operation.target_fingerprint.clone();
    let operation = restore.operation.operation_id.to_string();
    let abandon_phrase = crate::ceremony::derive_confirmation_phrase(
        crate::ceremony::RESTORE_ABANDON_PHRASE_PREFIX,
        &instance,
        &target,
        &operation,
    );
    let apply_phrase = crate::ceremony::derive_confirmation_phrase(
        crate::ceremony::RESTORE_APPLY_PHRASE_PREFIX,
        &instance,
        &target,
        &operation,
    );
    if !crate::ceremony::confirmation_phrase_satisfies(&abandon_phrase, &abandon_phrase) {
        return Err(
            "the helper's comparison does not accept the abandonment phrase composed for this operation; the control below would then be showing that it accepts nothing"
                .to_owned(),
        );
    }
    if crate::ceremony::confirmation_phrase_satisfies(&apply_phrase, &abandon_phrase) {
        return Err(
            "the helper's comparison accepts the APPLY phrase where the abandonment phrase is expected. An operator talked into consenting to a restore would then have consented to giving it up permanently, which is exactly the substitution ADR 0016's third phrase exists to prevent"
                .to_owned(),
        );
    }
    log.recordf(format_args!(
        "the abandonment phrase for this operation is accepted and the apply phrase at the same scope is refused; both are carried as digests only (abandon {}, apply {})",
        crate::ceremony::confirmation_phrase_digest(&abandon_phrase),
        crate::ceremony::confirmation_phrase_digest(&apply_phrase)
    ));

    restart_expect(
        id,
        "the broker issues an abandonment authorization bound to this operation and publishes the terminal outcome",
    );
    let authorization = journal
        .issue_restore_abandon_authorization(
            restore.operation.operation_id,
            peer().uid,
            peer().pid,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| {
            format!(
                "the broker refused to issue an abandonment authorization for this operation: {e}"
            )
        })?;
    let abandoned = journal
        .abandon(
            restore.operation.operation_id,
            &authorization,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| format!("the broker refused the abandonment this entry is about: {e}"))?;
    if abandoned.phase != RestorePhase::Abandoned {
        return Err(format!(
            "the abandonment left the operation at {}",
            abandoned.phase.as_str()
        ));
    }
    restore.phases.push(abandoned.phase.as_str().to_owned());
    restore
        .checkpoints
        .push(abandoned.last_checkpoint.as_str().to_owned());

    // --- The restart. ----------------------------------------------------
    restart_expect(
        id,
        "a broker composed fresh over the same protected root finds the abandonment durable, and neither resumes it nor serves from it",
    );
    let (_fresh_service, fresh) = restart_the_broker(&root, RestorePhase::Abandoned.as_str())?;
    let survived = fresh.read(abandoned.operation_id).map_err(|e| {
        format!("the restarted broker cannot read the abandoned operation back: {e}. An abandonment nothing can read afterwards is an abandonment a later process cannot know happened")
    })?;
    if survived != abandoned {
        return Err(format!(
            "the restarted broker read the abandoned operation back as {} and it was left as {}",
            survived.phase.as_str(),
            abandoned.phase.as_str()
        ));
    }
    if survived.is_resumable() {
        return Err(
            "the restarted broker reports the abandoned operation as resumable; ADR 0016 makes abandonment irreversible -- an abandoned operation can never serve and can never resume again"
                .to_owned(),
        );
    }
    if survived.serving_allowed() {
        return Err("the restarted broker considers the abandoned operation servable".to_owned());
    }
    // RESUME IS NOT PROBED WITH A ZERO AUTHORIZATION: resume's first guard
    // fails before the operation is read, so that call evidences the zero
    // value rather than irreversibility. What this entry can obtain is
    // stated instead: no apply authorization for the operation can be
    // issued, and the record reads back as not resumable — the same
    // predicate resume itself consults.
    restart_expect(
        id,
        "the restarted broker refuses to authorize any apply for the abandoned operation, so no route into a resume can be opened at all",
    );
    if fresh
        .issue_restore_apply_authorization_for_operation(
            survived.operation_id,
            peer().uid,
            peer().pid,
            OffsetDateTime::now_utc(),
        )
        .is_ok()
    {
        return Err(
            "the restarted broker authorized an apply for an abandoned operation. ADR 0016 makes abandonment irreversible: an operation given up permanently must not be re-authorizable after a restart"
                .to_owned(),
        );
    }
    restart_expect(
        id,
        "the same restarted broker DOES authorize an apply for an operation whose ticket still stands issued, so the refusal above is this operation's state and not an issuer that refuses everything",
    );
    let control = fresh
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("abandonment-control"),
            &admission_facts(PINNED_PG_TOOL_VERSION),
            Uuid::nil(),
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| format!("the restarted broker cannot mint a ticket at all ({e}), so the control below cannot be made"))?;
    if fresh
        .issue_restore_apply_authorization_for_operation(
            control.operation_id,
            peer().uid,
            peer().pid,
            OffsetDateTime::now_utc(),
        )
        .is_err()
    {
        return Err(
            "the restarted broker refused to authorize an apply for an operation whose ticket is still ISSUED; the refusal above is then an issuer that refuses everything"
                .to_owned(),
        );
    }
    if fresh
        .abandon(
            survived.operation_id,
            &authorization,
            OffsetDateTime::now_utc(),
        )
        .is_ok()
    {
        return Err(
            "the restarted broker abandoned an already-abandoned operation through the same authorization; the abandonment ceremony is one-use and a restart that makes it reusable resets that rule"
                .to_owned(),
        );
    }

    restart_expect(
        id,
        "the abandoned operation releases the serving barrier, so it blocks no later restore, while still being readable as the terminal record it is",
    );
    let (barrier, present) = fresh
        .inspect_restore_barrier()
        .map_err(|e| format!("the restarted broker cannot answer the serving barrier: {e}"))?;
    if present {
        return Err(format!(
            "the abandoned operation still occupies the serving barrier (it reports {} at {}); ADR 0016 requires an abandoned operation to release everything it held, or one abandonment would block every later restore",
            barrier.operation_id,
            barrier.phase.as_str()
        ));
    }

    let observation = compose_restart_observation(
        survived.phase.as_str(),
        &[
            assertion(
                "no_partial_serve",
                ASSERTION_HELD,
                "the restarted broker does not consider the abandoned operation servable and refuses to resume it, so nothing partial can be served from what it left behind",
            ),
            assertion(
                "no_ticket_replay",
                ASSERTION_HELD,
                "the restarted broker refuses to authorize any apply for this operation -- a refusal it makes by reading protected ticket state, since it authorizes only an operation's still-ISSUED ticket and this one's was consumed by its admission -- while the same broker DID authorize an apply for an operation whose ticket still stands issued; the abandonment authorization is separately refused a second time by the same broker",
            ),
            assertion(
                "no_duplicate_seal",
                ASSERTION_NOT_APPLICABLE,
                "an abandoned restore publishes no seal; the effect it publishes is the terminal outcome, and the restarted broker refuses to publish that twice",
            ),
            assertion(
                "no_artifact_delivery_from_quarantine",
                ASSERTION_NOT_ESTABLISHED,
                "no delivery was attempted; what is established is that the abandoned operation is never servable, so no delivery path is exposed on an instance holding it",
            ),
            assertion(
                "no_surviving_pre_restore_authority",
                ASSERTION_NOT_ESTABLISHED,
                "abandonment performs no authority reset -- ADR 0016's outcome is that the restore is given up, not that the authority is rotated -- so there is no invalidation census for a restarted process to read",
            ),
        ],
        RECORDED_AUTHORIZATION_CARRY_FORWARD,
    )?;
    {
        let mut records = fixture::records();
        records.record_restart_observation(id, RESTARTED_PROCESS, &observation)?;
        records.record_journal_walk(JournalWalk {
            operation_id: survived.operation_id.to_string(),
            phases: restore.phases.clone(),
            checkpoints: restore.checkpoints.clone(),
            // Two issued, one consumed: this operation's ticket, and the
            // control ticket the one-use assertion needs a live issuer to
            // answer for. The control is minted and never begun from.
            ticket_issued: 2,
            ticket_consumed: 1,
            boundary: format!("restore:{}", RestorePhase::Abandoned.as_str()),
            state_after_restart: survived.phase.as_str().to_owned(),
        })?;
    }
    log.recordf(format_args!(
        "the abandonment survived a broker restart: not resumable, not servable, barrier released, second abandonment refused"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// The sequence gate — `c06GateTheSequence` + `c06ProbeTheInstanceIsStillUsable`.
// ---------------------------------------------------------------------------

/// `c06GateTheSequence` — the I1 defence: check that the instance is still
/// usable between two entries, attributing damage to the entry that left it
/// that way. Upstream fails the run outright; in this port the outcome is
/// recorded on the NEXT entry with the predecessor named, because a Rust
/// test cannot abort the armed process — the attribution at the seam is
/// what the defence exists for, and a failed gate still leaves the run red
/// either way.
///
/// WHAT IT CAN AND CANNOT SEE: it probes reachability of the two stores the
/// whole chain runs on. It does NOT check their contents — that is each
/// entry's own subject, and a gate that tried would be a second, weaker
/// copy of scenario 7. Where the run never brought the shared stores up (no
/// live env), there is no shared instance to have damaged and the probe is
/// vacuous, stated rather than assumed.
pub(crate) fn gate_the_sequence(completed: &str, log: &mut ScenarioLog) -> Result<(), String> {
    match probe_the_instance_is_still_usable() {
        Ok(()) => {
            log.recordf(format_args!(
                "sequence gate after {completed}: the shared instance still answers"
            ));
            Ok(())
        }
        Err(e) => Err(format!(
            "after {completed} completed, the instance this continuous run shares is no longer usable: {e}.\n\nTHE ENTRY THAT LEFT IT THAT WAY IS {completed}. The remaining entries have not run and are NOT the cause; a sequence that broke in the middle evidences nothing after the break."
        )),
    }
}

/// `c06ProbeTheInstanceIsStillUsable` — the probe itself, separated so the
/// gate's message and its decision can be read apart. The object-store leg
/// is decided by a typed NOT_FOUND on a guaranteed-absent ready key: the
/// endpoint answered and the object is missing, which is reachability —
/// the same fact upstream's BucketExists asks.
pub(crate) fn probe_the_instance_is_still_usable() -> Result<(), String> {
    let Some(dsn) = scenario2::require_env(fixture::PG_DSN_ENV) else {
        return Ok(()); // no shared instance was ever brought up
    };
    let conn = scenario2::connect_pg(&dsn)
        .map_err(|e| format!("the database this run uses no longer accepts a connection: {e}"))?;
    conn.run(|c| {
        Box::pin(async move {
            sqlx::query("SELECT 1")
                .execute(&mut *c)
                .await
                .map(|_| ())
                .map_err(|e| {
                    central_foundation::failure::Failure::internal(
                        "c06",
                        format!("the database no longer answers a ping: {e}"),
                    )
                })
        })
    })
    .map_err(|e| e.to_string())?;

    if scenario2::s3_config().is_err() {
        return Ok(()); // the object store was never bound for this run
    }
    let s3 = scenario2::s3_config()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("compose the probe's object-store runtime: {e}"))?;
    let store = central_adapter_s3::S3ObjectStore::new(s3).map_err(|e| {
        format!("an object store client can no longer be built for this run's endpoint: {e}")
    })?;
    let absent = scenario2::derive_ready_key(
        &Uuid::now_v7().to_string(),
        &Uuid::now_v7().to_string(),
        "0",
    );
    use central_artifact::port::ObjectStore as _;
    match runtime.block_on(store.read(central_artifact::port::ObjectRef { key: absent })) {
        Ok(_) => Err(
            "the object store answered a key that was never written; the probe's absent control is present, so its readings cannot be trusted"
                .to_owned(),
        ),
        Err(e) if e.kind() == FailureKind::NotFound => Ok(()),
        Err(e) => Err(format!("the object store this run uses no longer answers: {e}")),
    }
}

// ---------------------------------------------------------------------------
// The nine catalogue entries — each a `slice_c::scenario` outcome, the nine
// restart injections of the continuous run.
// ---------------------------------------------------------------------------

macro_rules! restart_entry {
    ($name:ident, $id:literal, $body:expr) => {
        #[test]
        fn $name() {
            let runner = runner();
            if !runner.armed() {
                return;
            }
            let id = $id;
            slice_c::scenario(
                id,
                |profile| slice_c::unmet_precondition(id, profile),
                |_s| {
                    let mut log = ScenarioLog::new(id);
                    let body: fn(&str, &mut ScenarioLog) -> Result<(), String> = $body;
                    body(id, &mut log)
                },
            );
        }
    };
}

restart_entry!(
    c06_r1_restart_backup_admitted,
    "c06.r1.restart_backup_admitted",
    |id, log| {
        // Upstream gates once between the last scenario and the first
        // restart injection — this is that seam. The injections run on
        // their own roots, so nothing between r1 and r9 gates again.
        gate_the_sequence("c06.s10.throughput_below_floor", log)?;
        run_backup_boundary_restart(id, BackupPhase::Admitted, log)
    }
);
restart_entry!(
    c06_r2_restart_backup_dumping,
    "c06.r2.restart_backup_dumping",
    |id, log| run_backup_boundary_restart(id, BackupPhase::Dumping, log)
);
restart_entry!(
    c06_r3_restart_backup_inventory,
    "c06.r3.restart_backup_inventory",
    |id, log| run_backup_boundary_restart(id, BackupPhase::Inventory, log)
);
restart_entry!(
    c06_r4_restart_backup_sealing,
    "c06.r4.restart_backup_sealing",
    |id, log| run_backup_boundary_restart(id, BackupPhase::Sealing, log)
);
restart_entry!(
    c06_r5_restart_ticket_consumed,
    "c06.r5.restart_ticket_consumed",
    |id, log| run_restore_checkpoint_restart(id, RestoreCheckpoint::TicketConsumed, log)
);
restart_entry!(
    c06_r6_restart_database_replaced,
    "c06.r6.restart_database_replaced",
    |id, log| run_restore_checkpoint_restart(id, RestoreCheckpoint::DatabaseReplaced, log)
);
restart_entry!(
    c06_r7_restart_inventory_verified,
    "c06.r7.restart_inventory_verified",
    |id, log| run_restore_checkpoint_restart(id, RestoreCheckpoint::InventoryVerified, log)
);
restart_entry!(
    c06_r8_restart_authority_reset,
    "c06.r8.restart_authority_reset",
    |id, log| run_restore_checkpoint_restart(id, RestoreCheckpoint::AuthorityReset, log)
);
restart_entry!(
    c06_r9_restart_restore_abandoned,
    "c06.r9.restart_restore_abandoned",
    restart_after_abandonment
);

// --- CI-PORTABLE entry points. --------------------------------------------

/// `TestC06TheRestartObservationRulesRefuseWhatTheySayTheyRefuse` — the
/// composer's own guard, exercised over deliberately malformed inputs.
#[test]
fn the_restart_observation_rules_refuse_what_they_say_they_refuse() {
    let full = || -> Vec<RestartAssertion> {
        vec![
            assertion("no_partial_serve", ASSERTION_HELD, "a reason"),
            assertion("no_ticket_replay", ASSERTION_HELD, "a reason"),
            assertion("no_duplicate_seal", ASSERTION_HELD, "a reason"),
            assertion(
                "no_artifact_delivery_from_quarantine",
                ASSERTION_NOT_APPLICABLE,
                "a reason",
            ),
            assertion(
                "no_surviving_pre_restore_authority",
                ASSERTION_NOT_ESTABLISHED,
                "a reason",
            ),
        ]
    };
    let good = compose_restart_observation("verifying/inventory_verified", &full(), RECORDED_AUTHORIZATION_CARRY_FORWARD)
        .expect("the composer refused an observation that answers all five with reasons and carries a carry-forward label; every negative below would then be showing that it refuses everything");
    for key in RESTART_ASSERTION_KEYS {
        assert!(
            good.contains(&format!("{key}=")),
            "the composed observation answers {key} nowhere: {good}"
        );
    }
    assert!(good.contains(CARRY_FORWARD_MARKER));

    // An empty state.
    assert!(
        compose_restart_observation("", &full(), RECORDED_AUTHORIZATION_CARRY_FORWARD).is_err()
    );
    // An assertion set that is not exactly the five: one missing.
    let mut missing_one = full();
    missing_one.pop();
    assert!(
        compose_restart_observation(
            "applying",
            &missing_one,
            RECORDED_AUTHORIZATION_CARRY_FORWARD
        )
        .is_err()
    );
    // An unknown key in place of a declared one.
    let mut unknown = full();
    unknown[0] = assertion("no_such_thing", ASSERTION_HELD, "a reason");
    assert!(
        compose_restart_observation("applying", &unknown, RECORDED_AUTHORIZATION_CARRY_FORWARD)
            .is_err()
    );
    // A verdict outside the closed three.
    let mut bad_verdict = full();
    bad_verdict[0] = assertion("no_partial_serve", "probably_fine", "a reason");
    assert!(
        compose_restart_observation(
            "applying",
            &bad_verdict,
            RECORDED_AUTHORIZATION_CARRY_FORWARD
        )
        .is_err()
    );
    // A verdict with no reason, including "held".
    let mut no_reason = full();
    no_reason[0] = assertion("no_partial_serve", ASSERTION_HELD, " ");
    assert!(
        compose_restart_observation("applying", &no_reason, RECORDED_AUTHORIZATION_CARRY_FORWARD)
            .is_err()
    );
    // One assertion answered twice.
    let mut doubled = full();
    doubled.push(assertion("no_partial_serve", ASSERTION_HELD, "again"));
    assert!(
        compose_restart_observation("applying", &doubled, RECORDED_AUTHORIZATION_CARRY_FORWARD)
            .is_err()
    );
    // A label that does not open with the marker.
    assert!(compose_restart_observation("applying", &full(), "everything was fine").is_err());
    // No label at all.
    assert!(compose_restart_observation("applying", &full(), "").is_err());

    // The recorder's own refusals, over a fresh set rather than the
    // process-wide one: unknown id, non-injection id, an observation that
    // answers nothing, a missing assertion, no carry-forward label, and a
    // second observation over the same boundary.
    let mut records = fixture::RecordSet::default();
    let id = "c06.r1.restart_backup_admitted";
    assert!(
        records
            .check_restart_observation("c06.not.a.thing", RESTARTED_PROCESS, &good)
            .is_err()
    );
    assert!(
        records
            .check_restart_observation("c06.s2.corruption_detected", RESTARTED_PROCESS, &good)
            .is_err()
    );
    assert!(
        records
            .check_restart_observation(id, "a-daemon-nobody-declared", &good)
            .is_err()
    );
    assert!(
        records
            .check_restart_observation(id, RESTARTED_PROCESS, "")
            .is_err()
    );
    assert!(
        records
            .check_restart_observation(id, RESTARTED_PROCESS, "state | everything was fine")
            .is_err()
    );
    let dropped = good.replace("no_duplicate_seal=", "sealed_once=");
    assert!(
        records
            .check_restart_observation(id, RESTARTED_PROCESS, &dropped)
            .is_err()
    );
    records
        .record_restart_observation(id, RESTARTED_PROCESS, &good)
        .expect("the honest observation is recorded");
    assert!(
        records
            .record_restart_observation(id, RESTARTED_PROCESS, &good)
            .is_err()
    );
}

/// `TestC06TheDeclaredVocabularyCoversTheEmittedOne` — the five keys, the
/// three verdicts and the two carry-forward labels are exactly the set the
/// bodies may state.
#[test]
fn the_declared_restart_vocabulary_covers_the_emitted_one() {
    assert_eq!(RESTART_ASSERTION_KEYS.len(), 5);
    for key in RESTART_ASSERTION_KEYS {
        assert!(!key.is_empty() && !key.contains(' '));
    }
    assert_eq!(
        RESTART_VERDICTS,
        [
            ASSERTION_HELD,
            ASSERTION_NOT_APPLICABLE,
            ASSERTION_NOT_ESTABLISHED
        ]
    );
    assert!(RECORDED_AUTHORIZATION_CARRY_FORWARD.starts_with(CARRY_FORWARD_MARKER));
    assert!(SYNTHETIC_BACKUP_CARRY_FORWARD.starts_with(CARRY_FORWARD_MARKER));
    assert!(evidence::RESTART_PROCESSES.contains(&RESTARTED_PROCESS));
}
