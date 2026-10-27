//! `cmd/central/c06_slice_c_acceptance_test.go`, fixture half — the gates,
//! the privilege census, tool-version capture, the record set every scenario
//! accumulates into, and the synthetic streamed-body generator.
//!
//! The fixture deliberately does NOT stand up a weaker chain than
//! production's: where a Rust production surface the suite needs is not yet
//! reachable from an integration test (an in-process restore dispatch, the
//! private `open_restore_engine_root`, the operator-side backup client),
//! the scenario records an honest `precondition_failed` skip naming the
//! missing surface rather than composing a stub. Rule E-1 makes those skips
//! gate failures on an armed run — which is the truth: the run did not cover
//! them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::evidence::{
    AuthorityReset, CapacityReserveRecord, CeremonyRecord, CommandRecord, DestructiveConfirmation,
    ObservedMeasurements, PrivilegeProfile, ProtectedJournal, QuarantineResolutions,
    RestartObservation, ScenarioResult,
};

/// `CENTRAL_C06_EVIDENCE_DIR` — where the emitted artifact and transcripts
/// persist; records the evidence path the task requires.
pub const EVIDENCE_OUTPUT_ENV: &str = "CENTRAL_C06_EVIDENCE_DIR";
/// `CENTRAL_C06_CEREMONY_TTY` — the console the driver hands a ceremony child.
pub const CEREMONY_DEVICE_ENV: &str = "CENTRAL_C06_CEREMONY_TTY";
/// `CENTRAL_C06_OPERATOR_SECRET` — the operator secret the child env strips.
pub const OPERATOR_SECRET_ENV: &str = "CENTRAL_C06_OPERATOR_SECRET";
/// `CENTRAL_C06_GRANT_CEREMONY` — ADR 0031's grant-mode ceremony switch.
pub const GRANT_CEREMONY_ENV: &str = "CENTRAL_C06_GRANT_CEREMONY";
/// `CENTRAL_C06_PG_DSN` — the reference-host PostgreSQL the fixture uses.
pub const PG_DSN_ENV: &str = "CENTRAL_C06_PG_DSN";
/// `CENTRAL_C06_S3_ENDPOINT` etc. — the MinIO the fixture uses.
pub const S3_ENDPOINT_ENV: &str = "CENTRAL_C06_S3_ENDPOINT";

/// `c06EvidenceDirectory` — where the evidence artifact persists. Armed runs
/// only; defaults under `target/c06-evidence` (never the repository worktree,
/// so evidence bytes cannot dirty rule E-5's worktree check).
pub fn evidence_directory() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var(EVIDENCE_OUTPUT_ENV)
        && !dir.trim().is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    Ok(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/c06-evidence"))
}

// ---------------------------------------------------------------------------
// The privilege census (manifest field 16), measured at run start.
// ---------------------------------------------------------------------------

/// `c06PhysicalTTYClassOf` — classify a resolved fd-0 target into the
/// vocabulary `tty_class` admits (`serial`, `vt`); everything else is
/// "none"/not-a-console and reported by the classless classes.
pub fn physical_tty_class_of(target: &str) -> &'static str {
    if !crate::ceremony::ceremony_device_qualifies(target) {
        return "none";
    }
    // /dev/ttyS* and /dev/ttyUSB* are serial lines; /dev/ttyN is a VT.
    let name = target.trim_start_matches(PHYSICAL_TTY_PREFIX_RS);
    if name.starts_with('S') || name.starts_with("USB") {
        "serial"
    } else {
        "vt"
    }
}

const PHYSICAL_TTY_PREFIX_RS: &str = "/dev/tty";

/// `c06TTYClassOfSelf` — this process's fd 0, classified.
pub fn tty_class_of_self() -> (String, bool) {
    match std::fs::read_link("/proc/self/fd/0") {
        Ok(target) => {
            let target = target.to_string_lossy().into_owned();
            let class = physical_tty_class_of(&target);
            if class == "none" {
                (target, false)
            } else {
                (class.to_owned(), true)
            }
        }
        Err(_) => ("unresolved".to_owned(), false),
    }
}

/// `c06PAMStackPresent` — a PAM stack carrying the `central-helper` service.
/// Upstream reads /etc/pam.d/<service>; the Rust PAM boundary is linked
/// unconditionally, so presence is the service file's.
pub fn pam_stack_present() -> bool {
    Path::new("/etc/pam.d/central-helper").exists()
}

/// `c06AppArmorClass` — the confinement the census reports.
pub fn apparmor_class() -> String {
    match std::fs::read_to_string("/proc/self/attr/current") {
        Ok(profile) => {
            let profile = profile.trim().to_owned();
            if profile.is_empty() || profile == "unconfined" {
                "unconfined".to_owned()
            } else {
                format!("confined:{profile}")
            }
        }
        Err(_) => "absent".to_owned(),
    }
}

/// `c06BuildTags` — the conditional-build census. The Rust port compiles the
/// acceptance suite unconditionally and gates on the ARM env var, so the
/// equivalent fact recorded is the reference-host arm plus the always-on PAM
/// link (upstream's `pam` build tag, which `build.rs` -lpam makes constant).
pub fn build_tags() -> Vec<String> {
    vec!["referencehost".to_owned(), "pam".to_owned()]
}

/// `c06MeasurePrivilegeProfile` — the census itself.
pub fn measure_privilege_profile() -> PrivilegeProfile {
    let (tty, physical) = tty_class_of_self();
    PrivilegeProfile {
        uid: rustix::process::getuid().as_raw() as i64,
        gid: rustix::process::getgid().as_raw() as i64,
        pam_present: pam_stack_present(),
        pam_service: "central-helper".to_owned(),
        physical_tty: physical,
        tty_class: if physical { tty } else { "none".to_owned() },
        apparmor_profile: apparmor_class(),
        build_tags: build_tags(),
        cgo_enabled: true, // the Rust adapter links libpam natively, always
    }
}

// ---------------------------------------------------------------------------
// Corpus + synthetic bodies.
// ---------------------------------------------------------------------------

/// `c06OrdinaryArtifactCount` / `c06OrdinaryBodySize` / `c06StreamedBodySize`
/// — the corpus constants.
pub const ORDINARY_ARTIFACT_COUNT: usize = 24;
pub const ORDINARY_BODY_SIZE: usize = 4096;
pub const STREAMED_BODY_SIZE: u64 = 1536 * 1024 * 1024;

/// `c06SyntheticBlock` — the deterministic 32-byte block the streamed body is
/// built from at `offset`, so a 1.5 GiB body is generated and checked without
/// ever being held.
pub fn synthetic_block(label: &str, offset: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label.as_bytes());
    hash.update(b"\x00");
    hash.update(offset.to_le_bytes());
    let digest = hash.finalize();
    let mut block = [0u8; 32];
    block.copy_from_slice(&digest);
    block
}

/// `c06SyntheticBody` — the buffered form (used for ordinary bodies and for
/// the reader's differential check).
pub fn synthetic_body(label: &str, size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size);
    let mut offset = 0u64;
    while offset < size as u64 {
        let block = synthetic_block(label, offset);
        let take = (size as u64 - offset).min(32) as usize;
        body.extend_from_slice(&block[..take]);
        offset += take as u64;
    }
    body
}

/// `SyntheticBodyReader` — the streamed form: the same bytes, produced on
/// demand for the 1.5 GiB body.
pub struct SyntheticBodyReader {
    label: String,
    size: u64,
    offset: u64,
}

impl SyntheticBodyReader {
    pub fn new(label: &str, size: u64) -> Self {
        Self {
            label: label.to_owned(),
            size,
            offset: 0,
        }
    }
}

impl std::io::Read for SyntheticBodyReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.offset >= self.size {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < out.len() && self.offset < self.size {
            let block_offset = self.offset - (self.offset % 32);
            let block = synthetic_block(&self.label, block_offset);
            let index = (self.offset % 32) as usize;
            let take = (32 - index)
                .min(out.len() - written)
                .min((self.size - self.offset) as usize);
            out[written..written + take].copy_from_slice(&block[index..index + take]);
            self.offset += take as u64;
            written += take;
        }
        Ok(written)
    }
}

/// `TestC06SyntheticBodyReaderMatchesTheBufferedBody`.
#[test]
fn the_synthetic_body_reader_matches_the_buffered_body() {
    use std::io::Read as _;
    for size in [0usize, 1, 31, 32, 33, 4096, 8191] {
        let buffered = synthetic_body("c06-synthetic", size);
        let mut streamed = Vec::new();
        SyntheticBodyReader::new("c06-synthetic", size as u64)
            .read_to_end(&mut streamed)
            .unwrap();
        assert_eq!(buffered, streamed, "size {size}");
    }
}

// ---------------------------------------------------------------------------
// The record set — everything a run accumulates that the emitter cannot
// derive from the runner.
// ---------------------------------------------------------------------------

/// `c06RecordSet` — the mutable half of `EvidenceInputs`, plus the scenario
/// transcripts attached through `attach_log`.
///
/// The `pre_corruption`/`corrupted` slots are upstream's
/// `RecordPreCorruptionFingerprint`/`RecordPostCorruptionFingerprint`: a
/// fingerprint that fails its capture-side validation never reaches the set,
/// and each slot refuses a second record.
#[derive(Default)]
pub struct RecordSet {
    /// The pre-corruption fingerprint (validated). Upstream's scenario 1
    /// records it; this port's scenario 1 dispatches the operator command
    /// without seeding or fingerprinting, so scenario 2 records its own
    /// pre-injection capture — the same instance state under this port's
    /// seed-inside-s2 ordering.
    pub pre_corruption: Option<crate::fingerprint::StateFingerprint>,
    /// The post-corruption fingerprint scenario 2 records (validated as a
    /// corrupted instance — a body the store cannot answer is omitted, never
    /// placeholdered).
    pub corrupted: Option<crate::fingerprint::StateFingerprint>,
    pub observed: ObservedMeasurements,
    pub capacity_reserve: Vec<CapacityReserveRecord>,
    /// `capacityReserveRecorded` — set by
    /// [`RecordSet::record_capacity_reserve`] only; scenario 5's census is a
    /// single reading and a second one is refused.
    pub capacity_reserve_recorded: bool,
    pub ceremony_records: Vec<CeremonyRecord>,
    pub protected_journal: ProtectedJournal,
    /// `protectedJournalRecorded` — set by [`RecordSet::record_journal_walk`]
    /// only; the source-check in continuous_run.rs reads it to prove field 22
    /// is written by the walks, not by a direct assignment at emit time.
    pub protected_journal_recorded: bool,
    pub restart_observations: HashMap<String, RestartObservation>,
    pub destructive_confirmations: Vec<DestructiveConfirmation>,
    pub quarantine_resolutions: QuarantineResolutions,
    /// `quarantineResolutionsRecorded` — set by
    /// [`RecordSet::record_quarantine_resolutions`] only: field 25 emits
    /// `null` (not measured) until a real census is recorded, never a zeroed
    /// struct that would read as "measured, all zero".
    pub quarantine_resolutions_recorded: bool,
    pub authority_reset: AuthorityReset,
    /// `AuthorityResetFootprint` — the table names scenario 6 measured the
    /// mandated C05 reset moving, captured through the same fingerprint path
    /// scenario 7 compares against. `None` means s6 did not measure it, and
    /// s7 must refuse rather than assume the answer is "none".
    pub authority_reset_footprint: Option<Vec<String>>,
    /// `ToolVersionOutput` — the RAW `--version` outputs, parsed only by the
    /// emitter (upstream's record-raw rule: a pre-parsed caller records an
    /// assertion where field 17 asks for a measurement).
    pub tool_version_output: crate::evidence::ToolVersionOutput,
    /// `commandsRecorded` — set by [`RecordSet::record_command`] only:
    /// field 9 emits `null` (not measured) until a command is recorded,
    /// never `[]`, which would claim the run recorded its commands and
    /// found none. Field 7's image digests are measured at emit time
    /// (`c06MeasureImageDigests`), not recorded here.
    pub commands_recorded: bool,
    pub fixture_sha256: HashMap<String, String>,
    pub commands: Vec<CommandRecord>,
}

/// `c06JournalWalk` — one operation's traversal of the protected journal, as
/// governance field 22 carries it.
pub struct JournalWalk {
    pub operation_id: String,
    pub phases: Vec<String>,
    pub checkpoints: Vec<String>,
    pub ticket_issued: i64,
    pub ticket_consumed: i64,
    pub boundary: String,
    pub state_after_restart: String,
}

impl RecordSet {
    /// `RecordCommand` — the literal command line, env NAMES only, exit code,
    /// result and log digest. The command line must be one the run declares.
    /// Recording is also what marks field 9 measured: an emitted `[]` with
    /// `commands_recorded` false would be a claim, not a census.
    pub fn record_command(
        &mut self,
        id: &str,
        command_line: &str,
        env_names: Vec<String>,
        exit_code: i64,
        result: ScenarioResult,
        log_sha256: &str,
    ) {
        self.commands_recorded = true;
        self.commands.push(CommandRecord {
            id: id.to_owned(),
            command_line: command_line.to_owned(),
            env_names,
            exit_code,
            result,
            log_sha256: log_sha256.to_owned(),
        });
    }

    /// `RecordQuarantineResolutions` — the census governance field 25
    /// carries, recorded by whichever scenario measures the recovery audit
    /// store. A second record is refused: the census is a single reading at
    /// run end, and silently replacing it is how a field ends up naming a
    /// measurement nobody made. Until this is called the field emits the
    /// explicit `null` not-measured marker.
    pub fn record_quarantine_resolutions(
        &mut self,
        resolutions: QuarantineResolutions,
    ) -> Result<(), String> {
        self.check_quarantine_resolutions(&resolutions)?;
        self.quarantine_resolutions_recorded = true;
        self.quarantine_resolutions = resolutions;
        Ok(())
    }

    /// `checkQuarantineResolutions` — the decision the recorder makes,
    /// upstream's verbatim: a second census, a non-zero unresolved or
    /// still-open count at ready, a typed breakdown that does not total the
    /// typed resolutions, and a census that resolved nothing at all are each
    /// refused — the last because zero resolutions over zero findings is a
    /// run that never quarantined, not evidence that quarantine resolves.
    pub fn check_quarantine_resolutions(
        &self,
        resolutions: &QuarantineResolutions,
    ) -> Result<(), String> {
        if self.quarantine_resolutions_recorded {
            return Err(
                "the quarantine census was recorded twice; the second census describes a run whose findings something has already reconciled, and the emitter would carry it as the state at ready"
                    .to_owned(),
            );
        }
        if resolutions.unresolved != 0 {
            return Err(format!(
                "refusing to record a quarantine census with {} unresolved findings at ready: a non-zero unresolved count at ready is a contradiction of the design, because Ready is unreachable while any quarantine is open",
                resolutions.unresolved
            ));
        }
        if resolutions.open_findings_at_ready != 0 {
            return Err(format!(
                "refusing to record a quarantine census with {} findings still open at ready",
                resolutions.open_findings_at_ready
            ));
        }
        let by_reason = resolutions.by_reason.missing_body
            + resolutions.by_reason.checksum_mismatch
            + resolutions.by_reason.size_mismatch
            + resolutions.by_reason.unexpected_artifact
            + resolutions.by_reason.metadata_mismatch;
        let resolved = resolutions.reingested + resolutions.delete_finalized;
        if by_reason != resolved {
            return Err(format!(
                "refusing to record a quarantine census whose typed breakdown totals {by_reason} and whose typed resolutions total {resolved}: the two count the same findings, and a census where they disagree is one where a finding was resolved under a reason nobody recorded"
            ));
        }
        if resolved == 0 {
            return Err(
                "refusing to record a quarantine census that resolved nothing at all; an unresolved count of zero over zero findings says the run never quarantined anything, which is not evidence that quarantine can be resolved"
                    .to_owned(),
            );
        }
        Ok(())
    }

    /// `RecordCapacityReserve` — governance field 20's per-device entries,
    /// recorded through the check rather than appended, because the two
    /// refusals it exists to make — a release with no confirmation and an
    /// allocation with no release — are exactly what an unguarded append
    /// would carry. This is scenario 5's recorder: the kind it admits is
    /// `restore_reserve`.
    pub fn record_capacity_reserve(
        &mut self,
        records: Vec<CapacityReserveRecord>,
    ) -> Result<(), String> {
        self.check_capacity_reserve(&records)?;
        self.capacity_reserve = records;
        self.capacity_reserve_recorded = true;
        Ok(())
    }

    /// `checkCapacityReserve` — the decision scenario 5's reserve recorder
    /// makes, upstream's verbatim: nonempty, restore-reserve kind, a device
    /// identity, a declared role, a confirmation for every claimed release,
    /// nonzero reserve and allocation bytes (the zero-byte guard exists for
    /// the reader that lost the durable record's byte field), and no
    /// allocation that was never released. The s9 backup-admission entry is
    /// pushed through a different path by design — this recorder is s5's.
    pub fn check_capacity_reserve(&self, records: &[CapacityReserveRecord]) -> Result<(), String> {
        if self.capacity_reserve_recorded {
            return Err(
                "the capacity reserve census was recorded twice; the second describes a store something has already swept"
                    .to_owned(),
            );
        }
        if records.is_empty() {
            return Err(
                "refusing to record an empty capacity reserve census: a restore that allocated nothing evidences no reserve, and an empty array reads in the artifact exactly like a reserve that was cleanly released"
                    .to_owned(),
            );
        }
        for (index, record) in records.iter().enumerate() {
            if record.kind != "restore_reserve" {
                return Err(format!(
                    "refusing to record capacity_reserve[{index}] with kind {:?}: scenario 5 emits the restore reserve, and an entry carrying the backup-admission kind would attribute a C04 effect to C02",
                    record.kind
                ));
            }
            if record.device_id.trim().is_empty() {
                return Err(format!(
                    "refusing to record capacity_reserve[{index}] with no device identity: field 20 is per device, and an entry naming none cannot be attributed to one"
                ));
            }
            if !crate::evidence::CAPACITY_ROLES.contains(&record.role.as_str()) {
                return Err(format!(
                    "refusing to record capacity_reserve[{index}] with role {:?}, which is outside {:?}",
                    record.role,
                    crate::evidence::CAPACITY_ROLES
                ));
            }
            if record.released && record.release_confirmed_at.trim().is_empty() {
                return Err(format!(
                    "refusing to record capacity_reserve[{index}] as released with no confirmation: a release nothing confirms is a claim about the releasing process and not about the record it left behind"
                ));
            }
            // The zero-byte refusal precedes the unreleased one on purpose:
            // a field-name drift in the reader produces zeros rather than an
            // error, and zero-byte entries must be loud at record time, not
            // silent as a cleanly closed reserve.
            if record.reserve_bytes == 0 || record.allocated_bytes == 0 {
                return Err(format!(
                    "refusing to record capacity_reserve[{index}] with a {}-byte reserve and a {}-byte allocation: a reserve of no bytes is not a reserve, and an all-zero entry is what a reader that lost the record's byte field produces -- it must never pass as a closed effect",
                    record.reserve_bytes, record.allocated_bytes
                ));
            }
            if !record.released {
                return Err(format!(
                    "refusing to record capacity_reserve[{index}], which allocated {} bytes and was never released: an allocation with no confirmed release is an unclosed effect, not a pass",
                    record.allocated_bytes
                ));
            }
        }
        Ok(())
    }

    /// `RecordPreCorruptionFingerprint` — the baseline capture (upstream's
    /// scenario 1; this port's scenario 2 pre-injection capture):
    /// `validate` (the strict capture), exactly once, and its digest into the
    /// fixture digests the artifact carries.
    pub fn record_pre_corruption(
        &mut self,
        fingerprint: crate::fingerprint::StateFingerprint,
    ) -> Result<(), String> {
        fingerprint.validate()?;
        if self.pre_corruption.is_some() {
            return Err(
                "the pre-corruption fingerprint was recorded twice; the baseline scenario 7 compares against must be a single capture"
                    .to_owned(),
            );
        }
        self.fixture_sha256.insert(
            "state_fingerprint.pre_corruption".to_owned(),
            fingerprint.digest(),
        );
        self.pre_corruption = Some(fingerprint);
        Ok(())
    }

    /// `RecordPostCorruptionFingerprint` — scenario 2's corrupted-instance
    /// capture: `validate_as_corrupted` (the second capture's arm), exactly
    /// once, and its digest into the fixture digests.
    pub fn record_corrupted(
        &mut self,
        fingerprint: crate::fingerprint::StateFingerprint,
    ) -> Result<(), String> {
        fingerprint.validate_as_corrupted()?;
        if self.corrupted.is_some() {
            return Err(
                "the post-corruption fingerprint was recorded twice; the damaged-state scenario 7 must differ from must be a single capture"
                    .to_owned(),
            );
        }
        self.fixture_sha256.insert(
            "state_fingerprint.post_corruption".to_owned(),
            fingerprint.digest(),
        );
        self.corrupted = Some(fingerprint);
        Ok(())
    }

    /// `RecordRestartObservation` — what one boundary's restarted process
    /// observed, against the catalogue entry that boundary belongs to.
    /// Returns Err for every shape that would reach field 23 as a sentence
    /// a reviewer would read as evidence: unknown id, a non-injection entry,
    /// a process outside the emitter's vocabulary, an empty observation, a
    /// missing declared assertion or carry-forward label, or a second
    /// observation for one boundary.
    pub fn record_restart_observation(
        &mut self,
        id: &str,
        process: &str,
        observation: &str,
    ) -> Result<(), String> {
        self.check_restart_observation(id, process, observation)?;
        self.restart_observations.insert(
            id.to_owned(),
            RestartObservation {
                process: process.to_owned(),
                observed_after_restart: observation.to_owned(),
            },
        );
        Ok(())
    }

    /// `checkRestartObservation` — the decision the recorder makes,
    /// separated from the failing so the portable guards can exercise it.
    pub fn check_restart_observation(
        &self,
        id: &str,
        process: &str,
        observation: &str,
    ) -> Result<(), String> {
        let Some(entry) = crate::catalogue::lookup(id) else {
            return Err(format!(
                "refusing to record a restart observation for {id:?}: the C06 catalogue does not declare it, so the observation would be attached to nothing"
            ));
        };
        if entry.kind != crate::catalogue::Kind::RestartInjection {
            return Err(format!(
                "refusing to record a restart observation for {id}: it is a {:?} and only a restart injection reaches governance field 23",
                entry.kind
            ));
        }
        if !crate::evidence::RESTART_PROCESSES.contains(&process) {
            return Err(format!(
                "refusing to record {id} as having restarted {process:?}: the emitter admits only {:?}, and a process outside that set is refused at emission -- at the end of a run whose boundaries cannot be re-observed",
                crate::evidence::RESTART_PROCESSES
            ));
        }
        if observation.trim().is_empty() {
            return Err(format!(
                "refusing to record an empty observation for {id}: governance field 23 is a completeness claim over the boundary enumeration, and a boundary observed to be nothing is a boundary that was not observed"
            ));
        }
        for key in crate::continuous_run::RESTART_ASSERTION_KEYS {
            if !observation.contains(&format!("{key}=")) {
                return Err(format!(
                    "refusing to record an observation for {id} that never answers {key}; compose it through compose_restart_observation, which answers the five as a closed set"
                ));
            }
        }
        if !observation.contains(crate::continuous_run::CARRY_FORWARD_MARKER) {
            return Err(format!(
                "refusing to record an observation for {id} that carries no {:?} label; this field is the only one the ratified shape emits on a PASS, so an entry that does not state its open carry-forward here states it nowhere a reader of a green artifact can reach",
                crate::continuous_run::CARRY_FORWARD_MARKER
            ));
        }
        if self.restart_observations.contains_key(id) {
            return Err(format!(
                "refusing to record a second observation for {id}: the first is not recoverable once this one replaces it, and the artifact would carry whichever the run happened to record last"
            ));
        }
        Ok(())
    }

    /// `RecordJournalWalk` — accumulates governance field 22 from the walks
    /// the run actually performed. It accumulates rather than taking the
    /// whole journal at the end: a journal assembled at the end is a journal
    /// somebody wrote down, and the only defensible version of field 22 is
    /// the one each walk contributed as it happened.
    pub fn record_journal_walk(&mut self, walk: JournalWalk) -> Result<(), String> {
        self.check_journal_walk(&walk)?;
        self.protected_journal
            .operation_ids
            .push(walk.operation_id.clone());
        self.protected_journal
            .phase_sequences
            .insert(walk.operation_id.clone(), walk.phases);
        self.protected_journal
            .checkpoint_sequences
            .insert(walk.operation_id.clone(), walk.checkpoints);
        self.protected_journal
            .state_after_restart
            .insert(walk.boundary.clone(), walk.state_after_restart);
        self.protected_journal.ticket_issued += walk.ticket_issued;
        self.protected_journal.ticket_consumed += walk.ticket_consumed;
        self.protected_journal_recorded = true;
        Ok(())
    }

    /// `checkJournalWalk` — the decision the recorder makes, separated.
    pub fn check_journal_walk(&self, walk: &JournalWalk) -> Result<(), String> {
        let mut problems = Vec::new();
        if !is_opaque_identity(&walk.operation_id) {
            problems.push(
                "the walk names no opaque operation identity; governance section 3.1 admits only an opaque identifier here"
                    .to_owned(),
            );
        } else if self
            .protected_journal
            .phase_sequences
            .contains_key(&walk.operation_id)
        {
            problems.push(
                "an operation identity is walked twice; the second sequence replaces the first and the artifact then carries whichever was recorded last"
                    .to_owned(),
            );
        }
        if walk.phases.is_empty() {
            problems.push(
                "the walk records no phase sequence, so field 22 would carry an operation that stood in no state"
                    .to_owned(),
            );
        }
        if walk.checkpoints.is_empty() {
            problems.push("the walk records no checkpoint sequence".to_owned());
        }
        if walk.ticket_issued < 0 || walk.ticket_consumed < 0 {
            problems.push("a ticket count is negative".to_owned());
        }
        if walk.ticket_consumed > walk.ticket_issued {
            problems.push(
                "more tickets were consumed than were issued, which is the exact shape the one-use rule exists to make impossible; a journal reporting it is reporting its own accounting error as a finding"
                    .to_owned(),
            );
        }
        if walk.boundary.trim().is_empty() {
            problems.push(
                "the walk names no boundary, so its post-restart state would be filed under an empty key"
                    .to_owned(),
            );
        } else if self
            .protected_journal
            .state_after_restart
            .contains_key(&walk.boundary)
        {
            problems.push("a boundary's post-restart state is recorded twice".to_owned());
        }
        if walk.state_after_restart.trim().is_empty() {
            problems.push("the walk records no post-restart state for its boundary".to_owned());
        }
        if problems.is_empty() {
            return Ok(());
        }
        problems.sort();
        Err(format!(
            "refusing to record this protected-journal walk:\n  - {}",
            problems.join("\n  - ")
        ))
    }

    /// `RecordPerformedCeremony` — the only route to governance field 21.
    /// It refuses any record whose kind is not already carried by a
    /// DESTRUCTIVE CONFIRMATION: an authorization recorded directly against
    /// the broker is scenario 4's disclosed shortcut, and a field-21 entry
    /// for one would be the artifact asserting a ceremony that did not
    /// happen. An empty ceremony_records array is therefore not an omission:
    /// it is the run stating that it performed none.
    pub fn record_performed_ceremony(&mut self, record: CeremonyRecord) -> Result<(), String> {
        self.check_performed_ceremony(&record)?;
        self.ceremony_records.push(record);
        Ok(())
    }

    /// `checkPerformedCeremony` — the decision the recorder makes.
    pub fn check_performed_ceremony(&self, record: &CeremonyRecord) -> Result<(), String> {
        if !crate::evidence::CEREMONY_KINDS.contains(&record.kind.as_str()) {
            return Err(format!(
                "refusing to record a ceremony of kind {:?}: the emitter admits only {:?}",
                record.kind,
                crate::evidence::CEREMONY_KINDS
            ));
        }
        if !is_opaque_identity(&record.authorization_id)
            || !is_opaque_identity(&record.operation_id)
        {
            return Err(
                "refusing to record a ceremony whose authorization or operation identity is not opaque; governance section 3.1 admits only an opaque identifier here, never a ticket, nonce or token"
                    .to_owned(),
            );
        }
        for confirmation in &self.destructive_confirmations {
            if confirmation.operation_kind == record.kind {
                return Ok(());
            }
        }
        Err(format!(
            "refusing to record a {} ceremony: this run drove no destructive confirmation of that kind, so no ceremony of it was PERFORMED. An authorization recorded directly against the broker is scenario 4's disclosed shortcut and is still open, and an entry in governance field 21 for one would be the artifact asserting a ceremony that did not happen -- which is the single worst thing this document could do",
            record.kind
        ))
    }

    /// `RecordServerToolVersions` — the two field-17 readings no scenario
    /// owns: the PostgreSQL server this run queried and the toolchain this
    /// binary was built by. RAW output only; the emitter parses.
    pub fn record_server_tool_versions(
        &mut self,
        postgres_server: &str,
        toolchain: &str,
    ) -> Result<(), String> {
        if !self.tool_version_output.postgres_server.is_empty()
            || !self.tool_version_output.toolchain.is_empty()
        {
            return Err(
                "the server and toolchain versions were captured twice; the first reading is not recoverable once this one replaces it"
                    .to_owned(),
            );
        }
        crate::evidence::parse_postgres_server_version(postgres_server).map_err(|e| {
            format!("the emitter's own parser cannot read a server version out of what this run captured: {e}")
        })?;
        crate::evidence::parse_toolchain_version(toolchain).map_err(|e| {
            format!("the emitter's own parser cannot read a toolchain version out of what this run captured: {e}")
        })?;
        self.tool_version_output.postgres_server = postgres_server.to_owned();
        self.tool_version_output.toolchain = toolchain.to_owned();
        Ok(())
    }

    /// `RecordPGToolVersions` — the pg_dump/pg_restore `--version` readings
    /// scenario 1 takes, kept raw like their neighbours and refusing a
    /// second capture for the same reason.
    pub fn record_pg_tool_versions(
        &mut self,
        pg_dump: &str,
        pg_restore: &str,
    ) -> Result<(), String> {
        if !self.tool_version_output.pg_dump.is_empty()
            || !self.tool_version_output.pg_restore.is_empty()
        {
            return Err(
                "the pg_dump and pg_restore versions were captured twice; the first reading is not recoverable once this one replaces it, and governance field 17 is a record of what this run measured rather than of the last thing anybody asked"
                    .to_owned(),
            );
        }
        crate::evidence::parse_pg_tool_version("pg_dump", pg_dump).map_err(|e| {
            format!("the emitter's own parser cannot read a pg_dump version out of what this run captured: {e}")
        })?;
        crate::evidence::parse_pg_tool_version("pg_restore", pg_restore).map_err(|e| {
            format!("the emitter's own parser cannot read a pg_restore version out of what this run captured: {e}")
        })?;
        self.tool_version_output.pg_dump = pg_dump.to_owned();
        self.tool_version_output.pg_restore = pg_restore.to_owned();
        Ok(())
    }

    /// `RecordMinimumProfileMeasurement` — one reading against the field the
    /// emitter will carry it under. Refuses: a field the emitter does not
    /// carry; a non-positive reading (two of the five bounds are upper
    /// bounds that zero satisfies, so an absent measurement would otherwise
    /// pass as a met assertion); and a second reading over a field that
    /// already holds one.
    pub fn record_minimum_profile_measurement(
        &mut self,
        field: crate::profile::MeasurementField,
        observed: i64,
    ) -> Result<(), String> {
        self.check_minimum_profile_measurement(field, observed)?;
        self.set_minimum_profile_observation(field, observed)
    }

    /// `checkMinimumProfileMeasurement` — the decision, separated.
    pub fn check_minimum_profile_measurement(
        &self,
        field: crate::profile::MeasurementField,
        observed: i64,
    ) -> Result<(), String> {
        let existing = self
            .minimum_profile_observation(field)
            .map_err(|e| format!("refusing to record a minimum-profile measurement: {e}"))?;
        if observed <= 0 {
            return Err(format!(
                "refusing to record {} as {observed}: a non-positive reading is not a measurement that passed, it is one that was never taken -- and two of the five declared bounds are upper bounds that zero satisfies, so this would reach the artifact as a met assertion over a reading nobody made",
                field.as_str()
            ));
        }
        if existing != 0 {
            return Err(format!(
                "refusing to record {} a second time: it already holds {existing}, and the first reading is not recoverable once this one replaces it",
                field.as_str()
            ));
        }
        Ok(())
    }

    /// `minimumProfileObservation` — the emitted field for `field`, by name.
    /// An unknown field is an error, never a silent zero.
    pub fn minimum_profile_observation(
        &self,
        field: crate::profile::MeasurementField,
    ) -> Result<i64, String> {
        use crate::profile::MeasurementField as F;
        match field {
            F::BackupBytesPerSec => Ok(self.observed.backup_bytes_per_sec),
            F::RestoreBytesPerSec => Ok(self.observed.restore_bytes_per_sec),
            F::RestoreElapsedSeconds => Ok(self.observed.restore_elapsed_seconds),
            F::RepositoryBytes => Ok(self.observed.repository_bytes),
            F::DeviceFreeBytesMin => Ok(self.observed.device_free_bytes_min),
        }
    }

    /// `setMinimumProfileObservation` — the write half of the by-name pair.
    fn set_minimum_profile_observation(
        &mut self,
        field: crate::profile::MeasurementField,
        observed: i64,
    ) -> Result<(), String> {
        use crate::profile::MeasurementField as F;
        match field {
            F::BackupBytesPerSec => self.observed.backup_bytes_per_sec = observed,
            F::RestoreBytesPerSec => self.observed.restore_bytes_per_sec = observed,
            F::RestoreElapsedSeconds => self.observed.restore_elapsed_seconds = observed,
            F::RepositoryBytes => self.observed.repository_bytes = observed,
            F::DeviceFreeBytesMin => self.observed.device_free_bytes_min = observed,
        }
        Ok(())
    }

    /// `AuthorityResetFootprintRecorded`.
    pub fn authority_reset_footprint_recorded(&self) -> bool {
        self.authority_reset_footprint.is_some()
    }

    /// `RecordAuthorityResetFootprint` — the names of the tables scenario 6
    /// measured the mandated C05 reset moving, captured through the same
    /// fingerprint path. Exactly once; an unrecorded footprint must refuse
    /// in scenario 7 rather than be read as "none moved".
    pub fn record_authority_reset_footprint(
        &mut self,
        footprint: Vec<String>,
    ) -> Result<(), String> {
        if self.authority_reset_footprint.is_some() {
            return Err(
                "the authority-reset footprint was recorded twice; scenario 7 holds the moved-table set to exactly this measurement and a replaced measurement is not recoverable"
                    .to_owned(),
            );
        }
        self.authority_reset_footprint = Some(footprint);
        Ok(())
    }
}

/// `c06IsOpaqueIdentity` — the emitter's opacity rule applied at record
/// time: a non-UUID (or nil, or non-canonical) identifier is refused at the
/// walk that produced it rather than at the end of the run.
pub fn is_opaque_identity(value: &str) -> bool {
    value
        .parse::<uuid::Uuid>()
        .ok()
        .is_some_and(|parsed| !parsed.is_nil() && parsed.to_string() == value)
}

/// The process-wide record set the run's scenarios write through. Upstream
/// carries it on the harness; the Rust port's equivalent is the shared slot
/// the emitter reads — a per-body `RecordSet::default()` would discard every
/// record before `zz_emit_the_evidence` saw it.
static RECORDS: std::sync::OnceLock<std::sync::Mutex<RecordSet>> = std::sync::OnceLock::new();

/// `records` — a lock guard over the run's shared record set. A poisoned
/// lock is recovered: the records under it are not corrupted by a panic
/// above them, only the scenario that panicked is.
pub fn records() -> std::sync::MutexGuard<'static, RecordSet> {
    RECORDS
        .get_or_init(|| std::sync::Mutex::new(RecordSet::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Transcript-persist failures collected where a panic cannot go: a
/// `ScenarioLog` drop running during a scenario body's own unwind. Each is
/// the digest-committed bytes of one catalogue entry having failed to reach
/// the disk — an artifact emitted over them would register transcripts that
/// do not exist, so the emit step drains this list and refuses.
static TRANSCRIPT_FAILURES: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> =
    std::sync::OnceLock::new();

/// `recordTranscriptFailure` — a persist failure observed mid-unwind.
pub(crate) fn record_transcript_failure(message: String) {
    TRANSCRIPT_FAILURES
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(message);
}

/// `takeTranscriptFailures` — drains the collected failures; the emit step
/// refuses when any entry's transcript bytes could not be persisted.
pub(crate) fn take_transcript_failures() -> Vec<String> {
    TRANSCRIPT_FAILURES
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .split_off(0)
}

/// `declared_command_lines` — the closed vocabulary of command lines the run
/// may record into field 9 (`TestC06EveryCommandLineTheRunRecordsIsOneItDeclares`).
pub fn declared_command_lines() -> Vec<String> {
    vec![
        "central backup create".to_owned(),
        "central restore verify".to_owned(),
        "central restore apply".to_owned(),
        "central restore resume".to_owned(),
        "central restore abandon".to_owned(),
        "central grant issue".to_owned(),
    ]
}

/// `c06PGToolVersion` — run `<tool> --version` and capture raw output for the
/// emitter to parse.
pub fn pg_tool_version_output(tool: &str) -> Result<String, String> {
    let output = std::process::Command::new(tool)
        .arg("--version")
        .output()
        .map_err(|e| format!("recovery: {tool} --version could not run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "recovery: {tool} --version exited {}",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
