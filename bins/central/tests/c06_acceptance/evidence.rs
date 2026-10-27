//! `internal/recovery/{evidence,transcript}.go` — the C06 evidence artifact
//! shape, the emitter, the governance-section-3.1 prohibition scan, and the
//! transcript persistence that makes every `log_sha256` dereferenceable.
//!
//! Schema note for the Rust port: `tool_versions.go` carries the *build
//! toolchain* — upstream `go version`; here the `rustc`/`cargo` version —
//! under the same field name, and `dependency_lock_sha256` is recomputed over
//! `Cargo.lock` (upstream's governed `dependency-lock.json` equivalent). Both
//! divergences are by-construction, not by fiat: the artifact's schema
//! constant and field names are unchanged.

use std::collections::HashMap;
use std::io::Write as _;
use std::time::SystemTime;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::catalogue::{self, AttributionSource, Kind, Packet};
use crate::runner::{Census, Outcome, Result as OutcomeResult, Runner};

/// `EvidenceSchema` — the artifact's schema constant.
pub const EVIDENCE_SCHEMA: &str = "central.slice-c-recovery-acceptance/v1";
/// `EvidencePacket`.
pub const EVIDENCE_PACKET: &str = "C06";
/// `DependencyLockPath` — the repository-relative lockfile governance field 6
/// recomputes its digest from. Rust port: `Cargo.lock`.
pub const DEPENDENCY_LOCK_PATH: &str = "Cargo.lock";

// The declared bounds each measurement is carried with (governance field 11).
pub const BOUND_BACKUP_BYTES_PER_SEC: i64 = 16_777_216;
pub const BOUND_RESTORE_BYTES_PER_SEC: i64 = 16_777_216;
pub const BOUND_RESTORE_ELAPSED_SECONDS: i64 = 7200;
pub const BOUND_REPOSITORY_BYTES: i64 = 274_877_906_944;
pub const BOUND_DEVICE_FREE_BYTES_MIN: i64 = 5_368_709_120;

/// `ScenarioResult` — exactly two inhabitants; its default is `fail`, so a
/// record never populated cannot read as a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScenarioResult {
    passed: bool,
}

pub const SCENARIO_PASSED: ScenarioResult = ScenarioResult { passed: true };
pub const SCENARIO_FAILED: ScenarioResult = ScenarioResult { passed: false };

impl ScenarioResult {
    pub fn passed(self) -> bool {
        self.passed
    }
    pub const fn as_str(self) -> &'static str {
        if self.passed { "pass" } else { "fail" }
    }
}

impl Serialize for ScenarioResult {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ScenarioResult {
    /// A reader of a committed artifact must be unable to decode a skip.
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        match text.as_str() {
            "pass" => Ok(SCENARIO_PASSED),
            "fail" => Ok(SCENARIO_FAILED),
            other => Err(serde::de::Error::custom(format!(
                "recovery: {other:?} is not a scenario result; governance field 10 permits only pass and fail, and a skip belongs in the skip census"
            ))),
        }
    }
}

/// `PrivilegeProfile` — manifest field 16, measured at run start.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivilegeProfile {
    pub uid: i64,
    pub gid: i64,
    pub pam_present: bool,
    pub pam_service: String,
    pub physical_tty: bool,
    pub tty_class: String,
    pub apparmor_profile: String,
    pub build_tags: Vec<String>,
    /// `cgo_enabled` — the Rust port always links libpam natively, so the
    /// cgo/pam build distinction collapses to `true`; recorded as the
    /// upstream field it is.
    pub cgo_enabled: bool,
}

/// `ToolVersions` — manifest field 17, parsed from the tools' own output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolVersions {
    pub pg_dump: String,
    pub pg_restore: String,
    pub postgres_server: String,
    /// The build toolchain — `go version` upstream; `rustc`/`cargo` here.
    #[serde(rename = "go")]
    pub toolchain: String,
    pub central_restore_build_sha256: String,
    pub launcher_daemon_build_sha256: String,
}

/// `ToolVersionOutput` — raw captured output of each tool's version query.
#[derive(Debug, Clone, Default)]
pub struct ToolVersionOutput {
    pub pg_dump: String,
    pub pg_restore: String,
    pub postgres_server: String,
    /// The toolchain's version output — `go version` upstream; here
    /// `rustc -Vv`/`cargo version`.
    pub toolchain: String,
}

/// `BinaryDigests` — digests of the binaries the run executed.
#[derive(Debug, Clone, Default)]
pub struct BinaryDigests {
    pub central_restore_build_sha256: String,
    pub launcher_daemon_build_sha256: String,
}

/// `ScenarioRecord` — one entry of manifest field 10.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioRecord {
    pub id: String,
    pub packet: String,
    pub attribution: String,
    pub result: ScenarioResult,
    pub started_at: String,
    pub completed_at: String,
    pub log_sha256: String,
    /// Divergence on a failure; `null` on every passing entry.
    pub divergence: Option<String>,
}

/// `Measurement` — one observation beside the bound it is checked against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurement {
    pub observed: i64,
    pub bound: i64,
    pub relation: String,
}

/// `Measurements` — manifest field 11.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measurements {
    pub backup_bytes_per_sec: Measurement,
    pub restore_bytes_per_sec: Measurement,
    pub restore_elapsed_seconds: Measurement,
    pub repository_bytes: Measurement,
    pub device_free_bytes_min: Measurement,
}

/// `ObservedMeasurements` — what a run measured; the bounds are not here.
#[derive(Debug, Clone, Default)]
pub struct ObservedMeasurements {
    pub backup_bytes_per_sec: i64,
    pub restore_bytes_per_sec: i64,
    pub restore_elapsed_seconds: i64,
    pub repository_bytes: i64,
    pub device_free_bytes_min: i64,
}

/// `CapacityReserveRecord` — manifest field 20.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityReserveRecord {
    pub kind: String,
    pub device_id: String,
    pub role: String,
    pub free_bytes: u64,
    pub reserve_bytes: u64,
    pub floor_bytes: u64,
    pub projected_demand_bytes: u64,
    pub allocated_bytes: u64,
    pub released: bool,
    pub release_confirmed_at: String,
}

/// `CeremonyRecord` — manifest field 21. Opaque UUIDs only; never a nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyRecord {
    pub kind: String,
    pub authorization_id: String,
    pub operation_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub consumed_exactly_once: bool,
}

/// `ProtectedJournal` — manifest field 22.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtectedJournal {
    pub operation_ids: Vec<String>,
    pub phase_sequences: HashMap<String, Vec<String>>,
    pub checkpoint_sequences: HashMap<String, Vec<String>>,
    pub ticket_issued: i64,
    pub ticket_consumed: i64,
    pub state_after_restart: HashMap<String, String>,
}

/// `RestartInjectionRecord` — manifest field 23.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartInjectionRecord {
    pub id: String,
    pub boundary: String,
    pub process: String,
    pub observed_after_restart: String,
    pub result: ScenarioResult,
    pub log_sha256: String,
    pub divergence: Option<String>,
}

/// `RestartObservation` — what the live run saw after a restart.
#[derive(Debug, Clone)]
pub struct RestartObservation {
    pub process: String,
    pub observed_after_restart: String,
}

/// `DestructiveConfirmation` — manifest field 24. Phrase as digest only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructiveConfirmation {
    pub operation_kind: String,
    pub phrase_sha256: String,
    pub admitted_peer_uid: i64,
    pub rejected_redirected_input: bool,
    pub rejected_flag_substitution: bool,
    pub rejected_cross_ceremony_phrase: bool,
    pub confirmation_mode: String,
    pub rejected_missing_grant: bool,
    pub rejected_expired_grant: bool,
    pub rejected_spent_grant: bool,
    pub rejected_wrong_operation_grant: bool,
}

/// Confirmation modes for `confirmation_mode`.
pub const CONFIRMATION_MODE_TYPED_PHRASE: &str = "typed_phrase";
pub const CONFIRMATION_MODE_GRANT: &str = "grant";

/// `QuarantineResolutions` — manifest field 25.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineResolutions {
    pub reingested: i64,
    pub delete_finalized: i64,
    pub unresolved: i64,
    pub open_findings_at_ready: i64,
    pub by_reason: QuarantineByReason,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuarantineByReason {
    pub missing_body: i64,
    pub checksum_mismatch: i64,
    pub size_mismatch: i64,
    pub unexpected_artifact: i64,
    pub metadata_mismatch: i64,
}

/// `AuthorityReset` — manifest field 26.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthorityReset {
    pub restore_epoch_before: i64,
    pub restore_epoch_after: i64,
    pub security_epoch_before: i64,
    pub security_epoch_after: i64,
    pub invalidated: InvalidatedCounts,
    pub broker_tls_rekeyed: bool,
    pub bootstrap_generations_allocated: i64,
    pub aggregate_receipt_sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvalidatedCounts {
    pub sessions: i64,
    pub grants: i64,
    pub claims: i64,
    pub leases: i64,
    pub fences: i64,
    pub provider_bindings: i64,
    pub secret_references: i64,
}

/// `CommandRecord` — manifest field 9: literal command line, env NAMES only,
/// exit code, result, log digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub id: String,
    pub command_line: String,
    pub env_names: Vec<String>,
    pub exit_code: i64,
    pub result: ScenarioResult,
    pub log_sha256: String,
}

/// `ArtifactRecord` — one entry of governance field 12.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub id: String,
    pub checksum_sha256: String,
}

/// `RepoFacts` — the two things git is asked for.
pub struct RepoFacts {
    pub candidate_commit: String,
    pub worktree_clean: bool,
}

/// `EvidenceInputs` — everything the live run measured that the emitter
/// cannot derive from the runner. `repo_root` never reaches the artifact.
#[derive(Clone, Default)]
pub struct EvidenceInputs {
    pub generated_at: Option<SystemTime>,
    pub repo_root: String,
    pub tool_version_output: ToolVersionOutput,
    pub binary_digests: BinaryDigests,
    pub privilege_profile: PrivilegeProfile,
    pub observed: ObservedMeasurements,
    pub capacity_reserve: Vec<CapacityReserveRecord>,
    pub ceremony_records: Vec<CeremonyRecord>,
    pub protected_journal: ProtectedJournal,
    pub restart_observations: HashMap<String, RestartObservation>,
    pub destructive_confirmations: Vec<DestructiveConfirmation>,
    /// Governance field 25 — `None` is the not-measured marker: the census
    /// upstream runs against the recovery audit store is only emitted when a
    /// run actually recorded it through
    /// [`crate::fixture::RecordSet::record_quarantine_resolutions`]. A zeroed
    /// struct would read as "measured, all zero", which is a claim.
    pub quarantine_resolutions: Option<QuarantineResolutions>,
    pub authority_reset: AuthorityReset,
    /// Governance field 7 — `None` when the run named no containers for the
    /// emitter's `docker inspect` measurement; `{}` is a MEASURED-empty map
    /// and is not the same statement.
    pub image_digests: Option<HashMap<String, String>>,
    pub fixture_sha256: HashMap<String, String>,
    /// Governance field 9 — `None` when nothing was recorded through
    /// [`crate::fixture::RecordSet::record_command`]; `[]` would claim the
    /// run recorded its commands and found none.
    pub commands: Option<Vec<CommandRecord>>,
}

/// `Evidence` — slice-c-recovery-acceptance.json. Field order is the emitted
/// key order: serde writes struct fields in declaration order, so this
/// declaration is the artifact's canonical shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub schema: String,
    pub packet: String,
    pub generated_at: String,
    pub candidate_commit: String,
    /// Always true in an emitted artifact: [`emit`] refuses a dirty worktree
    /// under governance rule E-5 rather than recording one.
    pub worktree_clean: bool,
    pub privilege_profile: PrivilegeProfile,
    pub tool_versions: ToolVersions,
    pub catalogue_sha256: String,
    pub scenarios: Vec<ScenarioRecord>,
    pub skip_census: Census,
    pub measurements: Measurements,
    pub capacity_reserve: Vec<CapacityReserveRecord>,
    pub ceremony_records: Vec<CeremonyRecord>,
    pub protected_journal: ProtectedJournal,
    pub restart_injections: Vec<RestartInjectionRecord>,
    pub destructive_confirmations: Vec<DestructiveConfirmation>,
    /// `null` (not a zeroed struct) when no census was recorded — the
    /// not-measured marker, distinct from "measured, all zero".
    pub quarantine_resolutions: Option<QuarantineResolutions>,
    pub authority_reset: AuthorityReset,
    /// `null` (not `{}`) when the run named no containers to inspect.
    pub image_digests: Option<HashMap<String, String>>,
    pub fixture_sha256: HashMap<String, String>,
    pub dependency_lock_sha256: String,
    /// `null` (not `[]`) when the run recorded no commands.
    pub commands: Option<Vec<CommandRecord>>,
    /// Governance field 12 — makes every `log_sha256` dereferenceable.
    pub artifacts: Vec<ArtifactRecord>,
}

// ---------------------------------------------------------------------------
// transcripts (transcript.go)
// ---------------------------------------------------------------------------

/// `TranscriptArtifactSuffix`.
pub const TRANSCRIPT_ARTIFACT_SUFFIX: &str = ".transcript.txt";

/// `TranscriptArtifactID` — the artifacts-array id of one scenario's
/// transcript and the file name it is written to, in one function so the
/// name registered and the name written cannot drift apart.
pub fn transcript_artifact_id(scenario_id: &str) -> String {
    format!("{scenario_id}{TRANSCRIPT_ARTIFACT_SUFFIX}")
}

/// `TranscriptDigest`.
pub fn transcript_digest(transcript: &[u8]) -> String {
    crate::hex_lower(Sha256::digest(transcript))
}

/// `WriteTranscript` — persists one transcript into `directory` (mode 0600)
/// and returns the artifacts-array entry naming it. The digest is computed
/// from the bytes written, never supplied.
pub fn write_transcript(
    directory: &str,
    scenario_id: &str,
    transcript: &[u8],
) -> Result<ArtifactRecord, String> {
    if directory.trim().is_empty() {
        return Err(format!(
            "recovery: no directory was given to persist {scenario_id}'s transcript into; governance field 10's log_sha256 would then commit to text this run did not keep"
        ));
    }
    if scenario_id.trim().is_empty() {
        return Err("recovery: a transcript was offered with no catalogue id, so nothing in the artifacts array could name it".to_owned());
    }
    let record = ArtifactRecord {
        id: transcript_artifact_id(scenario_id),
        checksum_sha256: transcript_digest(transcript),
    };
    let path = std::path::Path::new(directory).join(&record.id);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("recovery: persisting {scenario_id}'s transcript failed: {e}"))?;
    file.write_all(transcript)
        .map_err(|e| format!("recovery: persisting {scenario_id}'s transcript failed: {e}"))?;
    Ok(record)
}

/// `ReadTranscript`.
pub fn read_transcript(directory: &str, artifact_id: &str) -> Result<(Vec<u8>, String), String> {
    let body = std::fs::read(std::path::Path::new(directory).join(artifact_id)).map_err(|e| {
        format!("recovery: the artifacts array registers {artifact_id} and it could not be read back: {e}")
    })?;
    let digest = transcript_digest(&body);
    Ok((body, digest))
}

/// `VerifyTranscripts` — re-reads every registered transcript, requires the
/// recomputed digest to equal BOTH the entry's checksum and the scenario's
/// log_sha256, and requires the array to cover every recorded entry.
pub fn verify_transcripts(directory: &str, evidence: &Evidence) -> Result<(), String> {
    let mut registered = HashMap::new();
    let mut problems = Vec::new();
    for record in &evidence.artifacts {
        if registered.insert(record.id.clone(), record).is_some() {
            problems.push(format!("the artifacts array registers {} more than once, so a reader cannot tell which entry a recomputation answers", record.id));
        }
    }
    let mut claimed = std::collections::HashSet::new();
    let check = |id: &str, log_digest: &str, problems: &mut Vec<String>| {
        let artifact_id = transcript_artifact_id(id);
        if log_digest.is_empty() {
            problems.push(format!("{id} carries no log_sha256 at all, so it registered no transcript and reaches a reviewer as a result with nothing behind it"));
            return;
        }
        match registered.get(&artifact_id) {
            None => problems.push(format!("{id} records log_sha256 {log_digest} and the artifacts array registers no {artifact_id}, so the digest commits to a transcript the document does not name")),
            Some(record) => {
                if record.checksum_sha256 != log_digest {
                    problems.push(format!("{id} records log_sha256 {log_digest} and the artifacts array registers checksum {} for {artifact_id}; the two must be the same digest or the entry is about a different file", record.checksum_sha256));
                    return;
                }
                match read_transcript(directory, &artifact_id) {
                    Err(e) => problems.push(e),
                    Ok((_, recomputed)) if recomputed != log_digest => problems.push(format!("{id}'s persisted transcript recomputes to {recomputed} and the document records log_sha256 {log_digest}; the file beside the artifact is not the text the artifact commits to")),
                    _ => {}
                }
            }
        }
    };
    for scenario in &evidence.scenarios {
        claimed.insert(transcript_artifact_id(&scenario.id));
        check(&scenario.id, &scenario.log_sha256, &mut problems);
    }
    for injection in &evidence.restart_injections {
        claimed.insert(transcript_artifact_id(&injection.id));
        check(&injection.id, &injection.log_sha256, &mut problems);
    }
    for id in registered.keys() {
        if !claimed.contains(id) {
            problems.push(format!("the artifacts array registers {id} and the document carries no scenario or restart injection of that name, so the entry answers to nothing in it"));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: the transcripts governance field 10's digests commit to are not retrievable from the emitted evidence:\n  - {}",
        problems.join("\n  - ")
    ))
}

/// `artifactsFor` — governance field 12's entry for every recorded digest.
fn artifacts_for(
    scenarios: &[ScenarioRecord],
    injections: &[RestartInjectionRecord],
) -> Vec<ArtifactRecord> {
    let mut records = Vec::new();
    for scenario in scenarios {
        if scenario.log_sha256.is_empty() {
            continue;
        }
        records.push(ArtifactRecord {
            id: transcript_artifact_id(&scenario.id),
            checksum_sha256: scenario.log_sha256.clone(),
        });
    }
    for injection in injections {
        if injection.log_sha256.is_empty() {
            continue;
        }
        records.push(ArtifactRecord {
            id: transcript_artifact_id(&injection.id),
            checksum_sha256: injection.log_sha256.clone(),
        });
    }
    records
}

// ---------------------------------------------------------------------------
// git and tool versions
// ---------------------------------------------------------------------------

/// `PorcelainRecords` — splits `git status --porcelain` output into records,
/// dropping lines that carry none. Cleanliness is decided from records, never
/// from capture length.
pub fn porcelain_records(raw: &str) -> Vec<String> {
    raw.split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_owned())
        .collect()
}

/// `WorktreeCleanFromPorcelain`.
pub fn worktree_clean_from_porcelain(raw: &str) -> bool {
    porcelain_records(raw).is_empty()
}

fn is_forty_hex(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `DeriveRepoFacts` — the candidate commit and the worktree's cleanliness.
/// `capture` runs `git` in the repo root and returns stdout only.
pub fn derive_repo_facts(
    capture: impl Fn(&str, &[&str]) -> Result<String, String>,
) -> Result<RepoFacts, String> {
    let commit = capture("git", &["rev-parse", "HEAD"])
        .map_err(|e| format!("recovery: reading the candidate commit failed: {e}"))?;
    let commit = commit.trim();
    if !is_forty_hex(commit) {
        return Err(format!(
            "recovery: {commit:?} is not a 40-hex object name, so it is not a candidate_commit a reviewer can resolve"
        ));
    }
    let porcelain = capture("git", &["status", "--porcelain"])
        .map_err(|e| format!("recovery: reading the worktree's cleanliness failed: {e}"))?;
    Ok(RepoFacts {
        candidate_commit: commit.to_owned(),
        worktree_clean: worktree_clean_from_porcelain(&porcelain),
    })
}

/// `ExecCapture` — runs commands in `dir`, returns stdout only; stderr is
/// deliberately not folded into the error because tool diagnostics carry
/// filesystem paths.
pub fn exec_capture(dir: &str) -> impl Fn(&str, &[&str]) -> Result<String, String> {
    let dir = dir.to_owned();
    move |name, args| {
        let output = std::process::Command::new(name)
            .args(args)
            .current_dir(&dir)
            .output()
            .map_err(|e| format!("recovery: {name} {} failed: {e}", args.join(" ")))?;
        if !output.status.success() {
            return Err(format!(
                "recovery: {name} {} failed: exit {}",
                args.join(" "),
                output.status
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// `ParsePGToolVersion` — `<tool> (PostgreSQL) <version>`; the tool named in
/// the output must be the tool asked, or the version is a drift the artifact
/// must not record.
pub fn parse_pg_tool_version(tool: &str, raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let (name, rest) = raw.split_once(" (PostgreSQL) ").ok_or_else(|| {
        format!("recovery: {tool}'s version output was not in the form \"<tool> (PostgreSQL) <version>\", so no version can be recorded for it")
    })?;
    if name != tool {
        return Err(format!(
            "recovery: the version output offered for {tool} was produced by {name}; a tool's version is read from that tool's own output"
        ));
    }
    let version: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if version.is_empty() || version.starts_with('.') {
        return Err(format!(
            "recovery: {tool}'s version output was not in the form \"<tool> (PostgreSQL) <version>\""
        ));
    }
    Ok(version)
}

/// `ParsePostgresServerVersion` — `PostgreSQL <version>` from SELECT version().
pub fn parse_postgres_server_version(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    let rest = raw.strip_prefix("PostgreSQL ").ok_or_else(|| {
        "recovery: the PostgreSQL server's version output did not begin \"PostgreSQL <version>\", so no server version can be recorded".to_owned()
    })?;
    let version: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if version.is_empty() {
        return Err("recovery: the PostgreSQL server's version output did not begin \"PostgreSQL <version>\"".to_owned());
    }
    Ok(version)
}

/// `ParseGoToolVersion` upstream; here the Rust toolchain. Accepts
/// `go version go<x> ...` verbatim (upstream compatibility) or
/// `rustc <x> ...`/`cargo <x> ...` — the build toolchain this artifact was
/// produced from, under the same emitted field.
pub fn parse_toolchain_version(raw: &str) -> Result<String, String> {
    let raw = format!("{} ", raw.trim());
    for prefix in ["go version go", "rustc ", "cargo "] {
        if let Some(rest) = raw.strip_prefix(prefix) {
            let version: String = rest.chars().take_while(|c| !c.is_whitespace()).collect();
            if !version.is_empty() {
                return Ok(if prefix == "go version go" {
                    format!("go{version}")
                } else {
                    version
                });
            }
        }
    }
    Err("recovery: the toolchain's version output was not in the form \"rustc <version>\" (or upstream's \"go version go<version> <platform>\"), so no toolchain version can be recorded".to_owned())
}

fn tool_versions_from(
    output: &ToolVersionOutput,
    digests: &BinaryDigests,
) -> Result<ToolVersions, String> {
    let pg_dump = parse_pg_tool_version("pg_dump", &output.pg_dump)?;
    let pg_restore = parse_pg_tool_version("pg_restore", &output.pg_restore)?;
    let server = parse_postgres_server_version(&output.postgres_server)?;
    let toolchain = parse_toolchain_version(&output.toolchain)?;
    for (field, value) in [
        (
            "central_restore_build_sha256",
            &digests.central_restore_build_sha256,
        ),
        (
            "launcher_daemon_build_sha256",
            &digests.launcher_daemon_build_sha256,
        ),
    ] {
        if !is_sha256(value) {
            return Err(format!(
                "recovery: tool_versions.{field} is not a sha-256 digest"
            ));
        }
    }
    Ok(ToolVersions {
        pg_dump,
        pg_restore,
        postgres_server: server,
        toolchain,
        central_restore_build_sha256: digests.central_restore_build_sha256.clone(),
        launcher_daemon_build_sha256: digests.launcher_daemon_build_sha256.clone(),
    })
}

/// `DependencyLockDigest` — recomputes governance field 6 from the lockfile.
pub fn dependency_lock_digest(repo_root: &str) -> Result<String, String> {
    let body = std::fs::read(std::path::Path::new(repo_root).join(DEPENDENCY_LOCK_PATH)).map_err(|e| {
        format!("recovery: the governed dependency lock could not be read from {DEPENDENCY_LOCK_PATH}: {e}")
    })?;
    Ok(crate::hex_lower(Sha256::digest(&body)))
}

/// `EvidenceDigest` — sha-256 over the artifact's exact bytes.
pub fn evidence_digest(document: &[u8]) -> String {
    crate::hex_lower(Sha256::digest(document))
}

// ---------------------------------------------------------------------------
// the prohibition scan (governance section 3.1)
// ---------------------------------------------------------------------------

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_uuid_pattern(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
}

fn is_env_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().enumerate().all(|(i, b)| {
            if i == 0 {
                b.is_ascii_alphabetic() || b == b'_'
            } else {
                b.is_ascii_alphanumeric() || b == b'_'
            }
        })
}

fn is_image_digest(value: &str) -> bool {
    // Upstream: `^[a-z0-9][a-z0-9._-]*(?:(?::[0-9]+)?/[a-z0-9._-]+)*@sha256:
    // [0-9a-f]{64}$` — a repository followed by an @sha256 pin and nothing
    // else; no mutable tag may appear anywhere.
    let Some((repo, digest)) = value.split_once("@sha256:") else {
        return false;
    };
    if !is_sha256(digest) || repo.is_empty() {
        return false;
    }
    let repo_byte =
        |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-');
    let first = repo.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    let mut rest = &repo.as_bytes()[1..];
    // host characters up to the first '/'; an optional ":<port>" may end the
    // host segment.
    while !rest.is_empty() && rest[0] != b'/' {
        if rest[0] == b':' {
            rest = &rest[1..];
            let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 {
                return false;
            }
            rest = &rest[digits..];
            break;
        }
        if !repo_byte(rest[0]) {
            return false;
        }
        rest = &rest[1..];
    }
    while rest.first() == Some(&b'/') {
        rest = &rest[1..];
        let segment = rest.iter().take_while(|b| repo_byte(**b)).count();
        if segment == 0 {
            return false;
        }
        rest = &rest[segment..];
    }
    rest.is_empty()
}

/// `confirmationPhrasePrefixes` — the destructive-ceremony phrase prefixes
/// upstream declares at `helper/confirmation_phrase.go`. They are unexported
/// there, so they are restated here; `ceremony.rs` pins the two lists
/// together by scanning the Rust `grant.rs`/`pam_ceremony.rs` source.
pub const CONFIRMATION_PHRASE_PREFIXES: [&str; 10] = [
    "RESET VERSION-ZERO",
    "RESTORE CENTRAL",
    "ABANDON RESTORE",
    "WIPE CENTRAL",
    "EXPORT CENTRAL",
    "IMPORT CENTRAL",
    "DELETE BACKUP",
    "PRUNE ARTIFACTS",
    "RESCUE CENTRAL",
    "PATCH CENTRAL",
];

const BASE64_BLOB_THRESHOLD: usize = 48;
const PATH_BOUNDARY: &str = " \t\n\r\u{b}\u{c}\"'=:(,[<;>&";
const WEAK_PATH_BOUNDARY: &str = ")|";

fn contains_dsn(value: &str) -> bool {
    if value.contains("://") {
        return true;
    }
    let lower = value.to_lowercase();
    for keyword in ["password", "passfile", "sslkey", "sslcert", "sslpassword"] {
        let mut rest = lower.as_str();
        while let Some(position) = rest.find(keyword) {
            let after = &rest[position + keyword.len()..];
            if after.trim_start().starts_with('=') {
                return true;
            }
            rest = &rest[position + keyword.len()..];
        }
    }
    false
}

fn contains_confirmation_phrase(value: &str) -> bool {
    CONFIRMATION_PHRASE_PREFIXES
        .iter()
        .any(|p| value.contains(p))
}

fn is_path_byte(candidate: u8) -> bool {
    candidate.is_ascii_alphanumeric() || matches!(candidate, b'.' | b'_' | b'-')
}

fn has_second_segment(rest: &[u8]) -> bool {
    for position in 0..rest.len() {
        if rest[position] == b'/' {
            return position + 1 < rest.len() && is_path_byte(rest[position + 1]);
        }
        if !is_path_byte(rest[position]) {
            return false;
        }
    }
    false
}

fn contains_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    for position in 0..bytes.len() {
        if bytes[position] != b'/' {
            continue;
        }
        if position + 1 >= bytes.len() || !is_path_byte(bytes[position + 1]) {
            continue;
        }
        if position == 0 {
            return true;
        }
        let previous = bytes[position - 1] as char;
        if PATH_BOUNDARY.contains(previous) {
            return true;
        }
        if WEAK_PATH_BOUNDARY.contains(previous) && has_second_segment(&bytes[position + 1..]) {
            return true;
        }
    }
    false
}

fn is_hex_digest(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_base64_byte(candidate: u8) -> bool {
    candidate.is_ascii_alphanumeric() || matches!(candidate, b'+' | b'/' | b'=')
}

fn run_is_blob_shaped(run: &str) -> bool {
    if run.len() < BASE64_BLOB_THRESHOLD {
        return false;
    }
    run.split('=')
        .any(|piece| piece.len() >= BASE64_BLOB_THRESHOLD && !is_hex_digest(piece))
}

/// `isBase64ShapedBlob` — whether the value CONTAINS an encoded blob: a
/// maximal run of base64 alphabet at the threshold, hex digests exempt.
fn is_base64_shaped_blob(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        if !is_base64_byte(bytes[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && is_base64_byte(bytes[end]) {
            end += 1;
        }
        if run_is_blob_shaped(&value[start..end]) {
            return true;
        }
        start = end;
    }
    false
}

fn contains_private_key(value: &str) -> bool {
    if let Some(position) = value.find("BEGIN") {
        let tail = &value[position..];
        let mut header = String::new();
        for c in tail.chars().skip(5) {
            if c.is_ascii_uppercase() || c.is_ascii_digit() || c == ' ' {
                header.push(c);
            } else {
                break;
            }
        }
        return header.contains("PRIVATE KEY");
    }
    false
}

fn prohibited_class(value: &str) -> &'static str {
    if contains_private_key(value) {
        "private key material"
    } else if contains_dsn(value) {
        "a DSN"
    } else if contains_confirmation_phrase(value) {
        "a confirmation phrase prefix"
    } else if contains_absolute_path(value) {
        "an absolute path"
    } else if is_base64_shaped_blob(value) {
        "a base64-shaped blob"
    } else {
        ""
    }
}

fn walk_json_strings(node: &serde_json::Value, path: &str, visit: &mut dyn FnMut(&str, &str)) {
    match node {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                visit(&format!("{path}.{key} (key)"), key);
                walk_json_strings(&map[key], &format!("{path}.{key}"), visit);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, element) in items.iter().enumerate() {
                walk_json_strings(element, &format!("{path}[{index}]"), visit);
            }
        }
        serde_json::Value::String(text) => visit(path, text),
        _ => {}
    }
}

/// `ScanProhibitions` — reads every string in an emitted artifact (values and
/// object keys alike) and reports the classes governance section 3.1 forbids.
/// The report names the JSON path and the class, never the offending value.
pub fn scan_prohibitions(document: &[u8]) -> Result<(), String> {
    let decoded: serde_json::Value = serde_json::from_slice(document).map_err(|e| {
        format!("recovery: the emitted artifact could not be re-read for the prohibition scan: {e}")
    })?;
    let mut problems = Vec::new();
    walk_json_strings(&decoded, "$", &mut |path, value| {
        let class = prohibited_class(value);
        if !class.is_empty() {
            problems.push(format!("{path} carries {class}"));
        }
    });
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: the emitted artifact carries material governance section 3.1 forbids:\n  - {}",
        problems.join("\n  - ")
    ))
}

// ---------------------------------------------------------------------------
// closed vocabularies (validateInputs reads the same lists producers compose)
// ---------------------------------------------------------------------------

pub const CAPACITY_RESERVE_KINDS: [&str; 2] = ["backup_admission", "restore_reserve"];
pub const CAPACITY_ROLES: [&str; 4] = [
    "postgres_data",
    "postgres_wal",
    "postgres_temp",
    "object_data",
];
pub const CEREMONY_KINDS: [&str; 3] = ["restore_apply", "restore_resume", "restore_abandon"];
/// `RestartProcessBrokerServiceRecomposedInProcess`.
pub const RESTART_PROCESS_BROKER_SERVICE_RECOMPOSED_IN_PROCESS: &str =
    "broker-service-recomposed-in-process";
pub const RESTART_PROCESSES: [&str; 5] = [
    "broker",
    "helper",
    "central-restore",
    "central",
    RESTART_PROCESS_BROKER_SERVICE_RECOMPOSED_IN_PROCESS,
];
pub const TTY_CLASSES: [&str; 2] = ["serial", "vt"];

fn in_vocabulary(value: &str, vocabulary: &[&str]) -> bool {
    vocabulary.contains(&value)
}

// ---------------------------------------------------------------------------
// the emitter
// ---------------------------------------------------------------------------

fn instant(at: SystemTime) -> String {
    let datetime: time::OffsetDateTime = at.into();
    datetime
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn parse_instant(value: &str) -> Option<SystemTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(SystemTime::from)
}

fn divergence(recorded: &str) -> Option<String> {
    if recorded.is_empty() {
        None
    } else {
        Some(recorded.to_owned())
    }
}

/// `marshalCanonical` — two-space indentation, no HTML escaping (serde_json
/// escapes nothing beyond the JSON-required set), one terminating newline.
fn marshal_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_string_pretty(value)
        .map_err(|e| format!("recovery: encoding the C06 evidence artifact failed: {e}"))?
        .into_bytes();
    bytes.push(b'\n');
    Ok(bytes)
}

/// `scenarioResultFor` — converts a recorded outcome into an emitted result;
/// refuses a skip.
fn scenario_result_for(outcome: &Outcome) -> Result<ScenarioResult, String> {
    match outcome.result {
        OutcomeResult::Pass => Ok(SCENARIO_PASSED),
        OutcomeResult::Fail => Ok(SCENARIO_FAILED),
        other => Err(format!(
            "recovery: {} recorded result {:?}, which is not an emittable scenario result; governance field 10 permits only pass and fail, and a skip belongs in the skip census",
            outcome.id,
            other.as_str()
        )),
    }
}

/// The run's recorded rows split the way the emitter emits them — scenario
/// records, restart-injection records, and the latest completion instant.
type RecordedRun = (
    Vec<ScenarioRecord>,
    Vec<RestartInjectionRecord>,
    Option<SystemTime>,
);

/// `recordsFrom` — the scenario list and the restart-injection list, built
/// from recorded outcomes in catalogue order and from nothing else.
fn records_from(
    runner: &Runner,
    observations: &HashMap<String, RestartObservation>,
) -> Result<RecordedRun, String> {
    let mut by_id: HashMap<String, Outcome> = HashMap::new();
    let mut latest: Option<SystemTime> = None;
    for outcome in runner.outcomes() {
        if latest.map(|l| outcome.completed_at > l).unwrap_or(true) {
            latest = Some(outcome.completed_at);
        }
        by_id.insert(outcome.id.clone(), outcome);
    }
    let catalogue = runner.catalogue();
    for id in observations.keys() {
        let declared = catalogue.iter().find(|e| e.id == id);
        if !matches!(declared.map(|e| e.kind), Some(Kind::RestartInjection)) {
            return Err(format!(
                "recovery: a restart observation was supplied for {id:?}, which the catalogue does not declare as a restart injection; the boundary it was meant for would carry none"
            ));
        }
    }
    let mut scenarios = Vec::new();
    let mut injections = Vec::new();
    for entry in &catalogue {
        let Some(outcome) = by_id.get(entry.id) else {
            continue; // unaccounted — reconcile already refused
        };
        if outcome.result == OutcomeResult::Skip {
            continue; // accounted for by the census
        }
        let result = scenario_result_for(outcome)?;
        if !outcome.log_sha256.is_empty() && !is_sha256(&outcome.log_sha256) {
            return Err(format!(
                "recovery: {} carries a log_sha256 that is not a sha-256 digest",
                entry.id
            ));
        }
        if entry.kind == Kind::RestartInjection {
            let observation = observations.get(entry.id).ok_or_else(|| {
                format!("recovery: {} ran but no state was observed after its restart; governance field 23 is a completeness claim over the boundary enumeration, so a boundary with no observation is a missing scenario", entry.id)
            })?;
            if !in_vocabulary(&observation.process, &RESTART_PROCESSES) {
                return Err(format!(
                    "recovery: {} names restarted process {:?}, which is outside the declared vocabulary {RESTART_PROCESSES:?}",
                    entry.id, observation.process
                ));
            }
            if observation.observed_after_restart.trim().is_empty() {
                return Err(format!(
                    "recovery: {} observed nothing after its restart",
                    entry.id
                ));
            }
            injections.push(RestartInjectionRecord {
                id: entry.id.to_owned(),
                boundary: entry.boundary.to_owned(),
                process: observation.process.clone(),
                observed_after_restart: observation.observed_after_restart.clone(),
                result,
                log_sha256: outcome.log_sha256.clone(),
                divergence: divergence(&outcome.divergence),
            });
            continue;
        }
        scenarios.push(ScenarioRecord {
            id: entry.id.to_owned(),
            packet: entry.packet.as_str().to_owned(),
            attribution: entry.attribution.as_str().to_owned(),
            result,
            started_at: instant(outcome.started_at),
            completed_at: instant(outcome.completed_at),
            log_sha256: outcome.log_sha256.clone(),
            divergence: divergence(&outcome.divergence),
        });
    }
    Ok((scenarios, injections, latest))
}

/// `measurement` — an absent reading is rendered absent, never as a zero
/// that an upper bound would read as a pass (final-review I-3).
fn measurement(observed: i64, bound: i64, relation: &str) -> Measurement {
    if observed <= 0 {
        return Measurement {
            observed,
            bound,
            relation: "not measured".to_owned(),
        };
    }
    Measurement {
        observed,
        bound,
        relation: relation.to_owned(),
    }
}

/// `measurementsFrom`.
pub fn measurements_from(observed: &ObservedMeasurements) -> Measurements {
    Measurements {
        backup_bytes_per_sec: measurement(
            observed.backup_bytes_per_sec,
            BOUND_BACKUP_BYTES_PER_SEC,
            ">=",
        ),
        restore_bytes_per_sec: measurement(
            observed.restore_bytes_per_sec,
            BOUND_RESTORE_BYTES_PER_SEC,
            ">=",
        ),
        restore_elapsed_seconds: measurement(
            observed.restore_elapsed_seconds,
            BOUND_RESTORE_ELAPSED_SECONDS,
            "<=",
        ),
        repository_bytes: measurement(observed.repository_bytes, BOUND_REPOSITORY_BYTES, "<"),
        device_free_bytes_min: measurement(
            observed.device_free_bytes_min,
            BOUND_DEVICE_FREE_BYTES_MIN,
            ">",
        ),
    }
}

fn sorted_keys(map: &HashMap<String, String>) -> Vec<&String> {
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    keys
}

fn validate_authority_reset(reset: &AuthorityReset) -> Result<(), String> {
    let mut problems = Vec::new();
    let counts: [(&str, i64); 7] = [
        ("sessions", reset.invalidated.sessions),
        ("grants", reset.invalidated.grants),
        ("claims", reset.invalidated.claims),
        ("leases", reset.invalidated.leases),
        ("fences", reset.invalidated.fences),
        ("provider_bindings", reset.invalidated.provider_bindings),
        ("secret_references", reset.invalidated.secret_references),
    ];
    let mut invalidated: i64 = 0;
    for (name, count) in counts {
        if count < 0 {
            problems.push(format!("authority_reset.invalidated.{name} is {count}; a negative count is not a measurement of anything"));
        }
        invalidated += count;
    }
    if reset.bootstrap_generations_allocated < 0 {
        problems.push(format!(
            "authority_reset.bootstrap_generations_allocated is {}",
            reset.bootstrap_generations_allocated
        ));
    }
    let asserted = reset.restore_epoch_before != 0
        || reset.restore_epoch_after != 0
        || reset.security_epoch_before != 0
        || reset.security_epoch_after != 0
        || invalidated != 0
        || reset.broker_tls_rekeyed
        || reset.bootstrap_generations_allocated != 0
        || !reset.aggregate_receipt_sha256.is_empty();
    if !asserted {
        if problems.is_empty() {
            return Ok(());
        }
        problems.sort();
        return Err(format!(
            "recovery: governance field 26 is not a coherent authority reset:\n  - {}",
            problems.join("\n  - ")
        ));
    }
    if !is_sha256(&reset.aggregate_receipt_sha256) {
        problems.push("authority_reset.aggregate_receipt_sha256 is not a sha-256 digest; it is the sole cryptographic anchor of governance field 26 and an asserted reset without it is a claim with nothing behind it".to_owned());
    }
    if reset.restore_epoch_after <= reset.restore_epoch_before {
        problems.push(format!("authority_reset names restore epochs {}->{}; C05's whole purpose is that the restored authority is replaced by a strictly higher epoch, and one that did not advance is authority the reset did not reach", reset.restore_epoch_before, reset.restore_epoch_after));
    }
    if reset.security_epoch_after <= reset.security_epoch_before {
        problems.push(format!("authority_reset names security epochs {}->{}; the same rule, and the epoch every pre-restore session is fenced by", reset.security_epoch_before, reset.security_epoch_after));
    }
    if reset.bootstrap_generations_allocated < 1 {
        problems.push("authority_reset.bootstrap_generations_allocated is under one for a reset that happened; a reset that allocated no fresh bootstrap generation leaves nothing for the instance to be re-adopted through".to_owned());
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: governance field 26 is not a coherent authority reset:\n  - {}",
        problems.join("\n  - ")
    ))
}

fn validate_protected_journal(journal: &ProtectedJournal) -> Result<(), String> {
    let mut problems = Vec::new();
    let mut known = std::collections::HashSet::new();
    for (index, id) in journal.operation_ids.iter().enumerate() {
        if !is_uuid_pattern(id) {
            problems.push(format!(
                "protected_journal.operation_ids[{index}] is not an opaque identifier"
            ));
            continue;
        }
        if !known.insert(id.clone()) {
            problems.push(format!(
                "protected_journal.operation_ids[{index}] repeats an operation already named"
            ));
        }
    }
    for (field, sequences) in [
        ("phase_sequences", &journal.phase_sequences),
        ("checkpoint_sequences", &journal.checkpoint_sequences),
    ] {
        let mut keys: Vec<&String> = sequences.keys().collect();
        keys.sort();
        for id in keys {
            if !is_uuid_pattern(id) {
                problems.push(format!(
                    "protected_journal.{field} is keyed by an identifier that is not opaque"
                ));
                continue;
            }
            if sequences[id].is_empty() {
                problems.push(format!("protected_journal.{field} carries an empty sequence, so field 22 names an operation that stood in no state"));
            }
            if !journal.operation_ids.is_empty() && !known.contains(id) {
                problems.push(format!("protected_journal.{field} names an operation that operation_ids does not, so the artifact walks an operation it does not admit having driven"));
            }
        }
    }
    if journal.ticket_issued < 0 || journal.ticket_consumed < 0 {
        problems.push("protected_journal carries a negative ticket count".to_owned());
    }
    if journal.ticket_consumed > journal.ticket_issued {
        problems.push(format!("protected_journal reports {} tickets consumed and {} issued; that is the exact shape the one-use rule exists to make impossible, and an artifact carrying it is reporting its own accounting error as a finding", journal.ticket_consumed, journal.ticket_issued));
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: governance field 22 is not a coherent protected journal:\n  - {}",
        problems.join("\n  - ")
    ))
}

fn validate_quarantine_resolutions(resolutions: &QuarantineResolutions) -> Result<(), String> {
    let mut problems = Vec::new();
    let counts: [(&str, i64); 9] = [
        ("reingested", resolutions.reingested),
        ("delete_finalized", resolutions.delete_finalized),
        ("unresolved", resolutions.unresolved),
        ("open_findings_at_ready", resolutions.open_findings_at_ready),
        ("by_reason.missing_body", resolutions.by_reason.missing_body),
        (
            "by_reason.checksum_mismatch",
            resolutions.by_reason.checksum_mismatch,
        ),
        (
            "by_reason.size_mismatch",
            resolutions.by_reason.size_mismatch,
        ),
        (
            "by_reason.unexpected_artifact",
            resolutions.by_reason.unexpected_artifact,
        ),
        (
            "by_reason.metadata_mismatch",
            resolutions.by_reason.metadata_mismatch,
        ),
    ];
    for (name, count) in counts {
        if count < 0 {
            problems.push(format!("quarantine_resolutions.{name} is {count}; a negative count is not a measurement of anything"));
        }
    }
    if resolutions.unresolved != 0 {
        problems.push(format!("quarantine_resolutions.unresolved is {}; a non-zero unresolved count at ready is a contradiction of the design and fails the gate, so it must not reach the artifact as a number a reviewer has to notice", resolutions.unresolved));
    }
    if resolutions.open_findings_at_ready != 0 {
        problems.push(format!("quarantine_resolutions.open_findings_at_ready is {}; an operation that reached ready with an open finding is the same contradiction stated the other way round", resolutions.open_findings_at_ready));
    }
    if problems.is_empty() {
        return Ok(());
    }
    problems.sort();
    Err(format!(
        "recovery: governance field 25 is not a coherent quarantine census:\n  - {}",
        problems.join("\n  - ")
    ))
}

/// `validateInputs` — the shape checks `emit` runs over its inputs.
pub fn validate_evidence_inputs(input: &EvidenceInputs) -> Result<(), String> {
    let profile = &input.privilege_profile;
    if profile.physical_tty && !in_vocabulary(&profile.tty_class, &TTY_CLASSES) {
        return Err(format!(
            "recovery: privilege_profile.tty_class is {:?}, which is outside the declared vocabulary {TTY_CLASSES:?}",
            profile.tty_class
        ));
    }
    for (index, reserve) in input.capacity_reserve.iter().enumerate() {
        if !in_vocabulary(&reserve.kind, &CAPACITY_RESERVE_KINDS) {
            return Err(format!(
                "recovery: capacity_reserve[{index}].kind is {:?}, which is outside the declared vocabulary {CAPACITY_RESERVE_KINDS:?}",
                reserve.kind
            ));
        }
        if !in_vocabulary(&reserve.role, &CAPACITY_ROLES) {
            return Err(format!(
                "recovery: capacity_reserve[{index}].role is {:?}, which is outside the declared vocabulary {CAPACITY_ROLES:?}",
                reserve.role
            ));
        }
        if reserve.device_id.trim().is_empty() {
            return Err(format!(
                "recovery: capacity_reserve[{index}].device_id is empty; devices appear as the opaque helper-derived identity"
            ));
        }
    }
    for (index, ceremony) in input.ceremony_records.iter().enumerate() {
        if !in_vocabulary(&ceremony.kind, &CEREMONY_KINDS) {
            return Err(format!(
                "recovery: ceremony_records[{index}].kind is {:?}, which is outside the declared vocabulary {CEREMONY_KINDS:?}",
                ceremony.kind
            ));
        }
        if !is_uuid_pattern(&ceremony.authorization_id) {
            return Err(format!(
                "recovery: ceremony_records[{index}].authorization_id is not an opaque identifier; governance section 3.1 admits only opaque IDs here, never a ticket, nonce or token"
            ));
        }
        if !is_uuid_pattern(&ceremony.operation_id) {
            return Err(format!(
                "recovery: ceremony_records[{index}].operation_id is not an opaque identifier"
            ));
        }
        let issued = parse_instant(&ceremony.issued_at).ok_or_else(|| {
            format!("recovery: ceremony_records[{index}].issued_at is {:?}, which is not an RFC 3339 instant; the authorization window is read off the broker's own record and a window that cannot be read is not one that was observed", ceremony.issued_at)
        })?;
        let expires = parse_instant(&ceremony.expires_at).ok_or_else(|| {
            format!("recovery: ceremony_records[{index}].expires_at is {:?}, which is not an RFC 3339 instant", ceremony.expires_at)
        })?;
        if expires <= issued {
            return Err(format!(
                "recovery: ceremony_records[{index}] expires at {}, at or before the {} it was issued at; an authorization with no window between those two instants was never live, so a record of one being consumed inside it describes something that cannot have happened",
                ceremony.expires_at, ceremony.issued_at
            ));
        }
        if !ceremony.consumed_exactly_once {
            return Err(format!(
                "recovery: ceremony_records[{index}].consumed_exactly_once is false. Governance field 21 records ceremonies this run PERFORMED, and the only route into it reads authorizations standing in the broker's consumed state -- which is the one-use property having held. A false here is either a record of an authorization that was never consumed, which is not a performed ceremony, or a claim that the broker consumed one twice, and an artifact must refuse rather than carry either quietly"
            ));
        }
    }
    for (index, confirmation) in input.destructive_confirmations.iter().enumerate() {
        if !in_vocabulary(&confirmation.operation_kind, &CEREMONY_KINDS) {
            return Err(format!(
                "recovery: destructive_confirmations[{index}].operation_kind is {:?}, which is outside the declared vocabulary {CEREMONY_KINDS:?}",
                confirmation.operation_kind
            ));
        }
        if !is_sha256(&confirmation.phrase_sha256) {
            return Err(format!(
                "recovery: destructive_confirmations[{index}].phrase_sha256 is not a sha-256 digest; the confirmation phrase appears only as a digest (governance section 3.1)"
            ));
        }
        if confirmation.confirmation_mode != CONFIRMATION_MODE_TYPED_PHRASE
            && confirmation.confirmation_mode != CONFIRMATION_MODE_GRANT
        {
            return Err(format!(
                "recovery: destructive_confirmations[{index}].confirmation_mode is {:?}, which names neither confirmation family; a reviewer cannot tell a typed-phrase entry from a grant entry without it",
                confirmation.confirmation_mode
            ));
        }
        let physical = confirmation.rejected_redirected_input
            || confirmation.rejected_flag_substitution
            || confirmation.rejected_cross_ceremony_phrase;
        let granted = confirmation.rejected_missing_grant
            || confirmation.rejected_expired_grant
            || confirmation.rejected_spent_grant
            || confirmation.rejected_wrong_operation_grant;
        if physical && granted {
            return Err(format!(
                "recovery: destructive_confirmations[{index}] sets negatives from both the typed-phrase and the grant family; one ceremony satisfies exactly one family and an entry claiming both describes something that cannot have happened"
            ));
        }
        if confirmation.confirmation_mode == CONFIRMATION_MODE_TYPED_PHRASE && granted {
            return Err(format!(
                "recovery: destructive_confirmations[{index}] is a typed-phrase entry carrying grant negatives"
            ));
        }
        if confirmation.confirmation_mode == CONFIRMATION_MODE_GRANT && physical {
            return Err(format!(
                "recovery: destructive_confirmations[{index}] is a grant entry carrying typed-phrase negatives"
            ));
        }
    }
    for (index, command) in input.commands.iter().flatten().enumerate() {
        if command.command_line.trim().is_empty() {
            return Err(format!(
                "recovery: commands[{index}] records no command line; governance field 9 requires the literal executed command line"
            ));
        }
        for name in &command.env_names {
            if !is_env_name(name) {
                return Err(format!(
                    "recovery: commands[{index}].env_names carries {name:?}, which is not a bare variable name; governance field 9 records the names of the variables that were set and never their values"
                ));
            }
        }
        if !command.log_sha256.is_empty() && !is_sha256(&command.log_sha256) {
            return Err(format!(
                "recovery: commands[{index}].log_sha256 is not a sha-256 digest"
            ));
        }
    }
    validate_authority_reset(&input.authority_reset)?;
    validate_protected_journal(&input.protected_journal)?;
    if let Some(resolutions) = &input.quarantine_resolutions {
        validate_quarantine_resolutions(resolutions)?;
    }
    if let Some(digests) = &input.image_digests {
        for name in sorted_keys(digests) {
            if !is_image_digest(&digests[name]) {
                return Err(format!(
                    "recovery: image_digests[{name:?}] is not an @sha256-pinned reference; governance field 7 requires every image pinned by digest with no mutable tag anywhere"
                ));
            }
        }
    }
    for name in sorted_keys(&input.fixture_sha256) {
        if !is_sha256(&input.fixture_sha256[name]) {
            return Err(format!(
                "recovery: fixture_sha256[{name:?}] is not a sha-256 digest; governance field 8 recomputes it"
            ));
        }
    }
    Ok(())
}

/// `Emit` — the bytes of slice-c-recovery-acceptance.json for a completed
/// run, or an error and no bytes. Its first act is reconciliation: an emitter
/// that succeeded on a partial run would produce a file that reads as a
/// completed acceptance.
pub fn emit(runner: &Runner, input: EvidenceInputs) -> Result<Vec<u8>, String> {
    runner.reconcile().map_err(|e| {
        format!("recovery: refusing to emit C06 evidence for a run reconciliation rejected: {e}")
    })?;
    let evidence = build(runner, &input)?;
    let document = marshal_canonical(&evidence)?;
    scan_prohibitions(&document)?;
    Ok(document)
}

fn build(runner: &Runner, input: &EvidenceInputs) -> Result<Evidence, String> {
    let generated_at = input.generated_at.ok_or_else(|| {
        "recovery: generated_at is unset; governance field 14 checks it against the run's own commands".to_owned()
    })?;
    let facts = derive_repo_facts(exec_capture(&input.repo_root))?;
    let versions = tool_versions_from(&input.tool_version_output, &input.binary_digests)?;
    let lock_digest = dependency_lock_digest(&input.repo_root)?;
    let (scenarios, injections, latest) = records_from(runner, &input.restart_observations)?;
    if let Some(latest) = latest
        && generated_at < latest
    {
        return Err(format!(
            "recovery: generated_at ({}) precedes the last recorded completion ({}); governance field 14 requires it to fall at or after everything the run recorded",
            instant(generated_at),
            instant(latest)
        ));
    }
    if generated_at > SystemTime::now() {
        return Err(format!(
            "recovery: generated_at ({}) is later than the emitter's own clock; a timestamp naming a moment that has not happened is a claim, not a record of when this artifact was produced",
            instant(generated_at)
        ));
    }
    validate_evidence_inputs(input)?;
    // The artifact index derives from both sets before they move into the
    // record — a transcript's registration is indexed from the same records
    // the emitter emits.
    let artifacts = artifacts_for(&scenarios, &injections);
    let evidence = Evidence {
        schema: EVIDENCE_SCHEMA.to_owned(),
        packet: EVIDENCE_PACKET.to_owned(),
        generated_at: instant(generated_at),
        candidate_commit: facts.candidate_commit,
        worktree_clean: facts.worktree_clean,
        privilege_profile: input.privilege_profile.clone(),
        tool_versions: versions,
        catalogue_sha256: catalogue::catalogue_digest(&runner.catalogue()),
        scenarios,
        skip_census: runner.census(),
        measurements: measurements_from(&input.observed),
        capacity_reserve: input
            .capacity_reserve
            .iter()
            .map(|r| CapacityReserveRecord {
                kind: r.kind.clone(),
                device_id: r.device_id.clone(),
                role: r.role.clone(),
                free_bytes: r.free_bytes,
                reserve_bytes: r.reserve_bytes,
                floor_bytes: r.floor_bytes,
                projected_demand_bytes: r.projected_demand_bytes,
                allocated_bytes: r.allocated_bytes,
                released: r.released,
                release_confirmed_at: r.release_confirmed_at.clone(),
            })
            .collect(),
        ceremony_records: input
            .ceremony_records
            .iter()
            .map(|c| CeremonyRecord {
                kind: c.kind.clone(),
                authorization_id: c.authorization_id.clone(),
                operation_id: c.operation_id.clone(),
                issued_at: c.issued_at.clone(),
                expires_at: c.expires_at.clone(),
                consumed_exactly_once: c.consumed_exactly_once,
            })
            .collect(),
        protected_journal: ProtectedJournal {
            operation_ids: input.protected_journal.operation_ids.clone(),
            phase_sequences: input.protected_journal.phase_sequences.clone(),
            checkpoint_sequences: input.protected_journal.checkpoint_sequences.clone(),
            ticket_issued: input.protected_journal.ticket_issued,
            ticket_consumed: input.protected_journal.ticket_consumed,
            state_after_restart: input.protected_journal.state_after_restart.clone(),
        },
        restart_injections: injections,
        destructive_confirmations: input
            .destructive_confirmations
            .iter()
            .map(|d| DestructiveConfirmation {
                operation_kind: d.operation_kind.clone(),
                phrase_sha256: d.phrase_sha256.clone(),
                admitted_peer_uid: d.admitted_peer_uid,
                rejected_redirected_input: d.rejected_redirected_input,
                rejected_flag_substitution: d.rejected_flag_substitution,
                rejected_cross_ceremony_phrase: d.rejected_cross_ceremony_phrase,
                confirmation_mode: d.confirmation_mode.clone(),
                rejected_missing_grant: d.rejected_missing_grant,
                rejected_expired_grant: d.rejected_expired_grant,
                rejected_spent_grant: d.rejected_spent_grant,
                rejected_wrong_operation_grant: d.rejected_wrong_operation_grant,
            })
            .collect(),
        // None passes straight through — a not-measured census emits null,
        // never a zeroed struct that would read as "measured, all zero".
        quarantine_resolutions: input.quarantine_resolutions.as_ref().map(|r| {
            QuarantineResolutions {
                reingested: r.reingested,
                delete_finalized: r.delete_finalized,
                unresolved: r.unresolved,
                open_findings_at_ready: r.open_findings_at_ready,
                by_reason: QuarantineByReason {
                    missing_body: r.by_reason.missing_body,
                    checksum_mismatch: r.by_reason.checksum_mismatch,
                    size_mismatch: r.by_reason.size_mismatch,
                    unexpected_artifact: r.by_reason.unexpected_artifact,
                    metadata_mismatch: r.by_reason.metadata_mismatch,
                },
            }
        }),
        authority_reset: AuthorityReset {
            restore_epoch_before: input.authority_reset.restore_epoch_before,
            restore_epoch_after: input.authority_reset.restore_epoch_after,
            security_epoch_before: input.authority_reset.security_epoch_before,
            security_epoch_after: input.authority_reset.security_epoch_after,
            invalidated: InvalidatedCounts {
                sessions: input.authority_reset.invalidated.sessions,
                grants: input.authority_reset.invalidated.grants,
                claims: input.authority_reset.invalidated.claims,
                leases: input.authority_reset.invalidated.leases,
                fences: input.authority_reset.invalidated.fences,
                provider_bindings: input.authority_reset.invalidated.provider_bindings,
                secret_references: input.authority_reset.invalidated.secret_references,
            },
            broker_tls_rekeyed: input.authority_reset.broker_tls_rekeyed,
            bootstrap_generations_allocated: input.authority_reset.bootstrap_generations_allocated,
            aggregate_receipt_sha256: input.authority_reset.aggregate_receipt_sha256.clone(),
        },
        image_digests: input.image_digests.clone(),
        fixture_sha256: input.fixture_sha256.clone(),
        dependency_lock_sha256: lock_digest,
        commands: input.commands.as_ref().map(|commands| {
            commands
                .iter()
                .map(|c| CommandRecord {
                    id: c.id.clone(),
                    command_line: c.command_line.clone(),
                    env_names: c.env_names.clone(),
                    exit_code: c.exit_code,
                    result: c.result,
                    log_sha256: c.log_sha256.clone(),
                })
                .collect()
        }),
        artifacts,
    };
    // Governance rule E-5: a dirty-worktree run is implementation evidence
    // only; refusing is the only disposition that cannot be misused later.
    // The emitted field is read back, so a hard-coded true would disable the
    // refusal.
    if !evidence.worktree_clean {
        return Err("recovery: refusing to emit C06 evidence from a dirty worktree; governance rule E-5: \"A dirty-worktree result is implementation evidence only. Acceptance never runs from a dirty worktree.\" This run is implementation evidence only and no acceptance artifact is produced for it".to_owned());
    }
    Ok(evidence)
}

#[allow(dead_code)]
fn _packet_and_attribution_used(p: Packet, a: AttributionSource) -> (&'static str, &'static str) {
    (p.as_str(), a.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scenario_result_emits_only_pass_or_fail() {
        assert_eq!(serde_json::to_string(&SCENARIO_PASSED).unwrap(), "\"pass\"");
        assert_eq!(serde_json::to_string(&SCENARIO_FAILED).unwrap(), "\"fail\"");
        assert!(serde_json::from_str::<ScenarioResult>("\"skip\"").is_err());
    }

    #[test]
    fn the_prohibition_scan_sees_paths_dsns_phrases_and_blobs() {
        assert_eq!(
            prohibited_class("dump failed; see /var/lib/x/y"),
            "an absolute path"
        );
        assert_eq!(prohibited_class("postgres://u:p@h/db"), "a DSN");
        assert_eq!(
            prohibited_class("typed RESTORE CENTRAL abc"),
            "a confirmation phrase prefix"
        );
        assert_eq!(prohibited_class(&"QUJD".repeat(20)), "a base64-shaped blob");
        assert_eq!(prohibited_class("docker.io/library/postgres@sha256:"), "");
        // A labelled sha-256 digest is not a blob.
        assert_eq!(prohibited_class(&format!("sha256={}", "a".repeat(64))), "");
        // Weak-boundary single-segment path is admitted prose, a real path is not.
        assert_eq!(prohibited_class("(expected 5)/got 3"), "");
        assert_eq!(prohibited_class("rows | /bin/cat tail"), "an absolute path");
    }

    #[test]
    fn porcelain_records_read_records_not_bytes() {
        assert!(worktree_clean_from_porcelain(""));
        assert!(worktree_clean_from_porcelain("\n\r\n"));
        assert!(!worktree_clean_from_porcelain(" M file.rs\n"));
    }

    #[test]
    fn tool_versions_refuse_the_wrong_tool() {
        assert_eq!(
            parse_pg_tool_version("pg_dump", "pg_dump (PostgreSQL) 16.14 (Debian)").unwrap(),
            "16.14"
        );
        assert!(parse_pg_tool_version("pg_restore", "pg_dump (PostgreSQL) 16.14").is_err());
        assert_eq!(
            parse_postgres_server_version("PostgreSQL 16.14 on x86_64").unwrap(),
            "16.14"
        );
        assert_eq!(
            parse_toolchain_version("go version go1.25.0 linux/amd64").unwrap(),
            "go1.25.0"
        );
        assert_eq!(
            parse_toolchain_version("rustc 1.88.0 (6b00bc388 2025-06-23)").unwrap(),
            "1.88.0"
        );
    }

    #[test]
    fn transcripts_are_registered_read_back_and_verified() {
        let dir = std::env::temp_dir().join(format!("c06-transcript-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let record =
            write_transcript(dir.to_str().unwrap(), "c06.s1.backup_create", b"log body").unwrap();
        assert_eq!(record.id, "c06.s1.backup_create.transcript.txt");
        let (body, digest) = read_transcript(dir.to_str().unwrap(), &record.id).unwrap();
        assert_eq!(body, b"log body");
        assert_eq!(digest, record.checksum_sha256);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
