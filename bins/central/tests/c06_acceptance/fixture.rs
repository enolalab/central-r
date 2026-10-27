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
    /// The pre-corruption fingerprint scenario 1 records (validated).
    pub pre_corruption: Option<crate::fingerprint::StateFingerprint>,
    /// The post-corruption fingerprint scenario 2 records (validated as a
    /// corrupted instance — a body the store cannot answer is omitted, never
    /// placeholdered).
    pub corrupted: Option<crate::fingerprint::StateFingerprint>,
    pub observed: ObservedMeasurements,
    pub capacity_reserve: Vec<CapacityReserveRecord>,
    pub ceremony_records: Vec<CeremonyRecord>,
    pub protected_journal: ProtectedJournal,
    pub restart_observations: HashMap<String, RestartObservation>,
    pub destructive_confirmations: Vec<DestructiveConfirmation>,
    pub quarantine_resolutions: QuarantineResolutions,
    pub authority_reset: AuthorityReset,
    pub image_digests: HashMap<String, String>,
    pub fixture_sha256: HashMap<String, String>,
    pub commands: Vec<CommandRecord>,
}

impl RecordSet {
    /// `RecordCommand` — the literal command line, env NAMES only, exit code,
    /// result and log digest. The command line must be one the run declares.
    pub fn record_command(
        &mut self,
        id: &str,
        command_line: &str,
        env_names: Vec<String>,
        exit_code: i64,
        result: ScenarioResult,
        log_sha256: &str,
    ) {
        self.commands.push(CommandRecord {
            id: id.to_owned(),
            command_line: command_line.to_owned(),
            env_names,
            exit_code,
            result,
            log_sha256: log_sha256.to_owned(),
        });
    }

    /// `RecordPreCorruptionFingerprint` — scenario 1's baseline capture:
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
