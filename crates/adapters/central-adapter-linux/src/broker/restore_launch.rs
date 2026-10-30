//! `restore_launch.rs` — the port of upstream
//! `internal/adapter/authority/broker/restore_launch.go` and
//! `restore_launch_issuer.go`: the single-flight launch-evidence
//! record for the restore engine plus its client-side issuer.
//!
//! Unlike [`super::backup_launch::BackupLaunchStore`], which tracks
//! many concurrent workers keyed by evidence ID, the restore engine is
//! single-flight by design: at most one root recovery run is ever
//! legitimately in progress, so this store holds one record at the
//! fixed path `restore-launch/current.json`.
//!
//! The record binds two distinct process identities — the engine's
//! (`peer_pid`/`process_start`/`executable`, ADR 0015) and the root
//! helper's (`parent_pid`/`helper_executable`/`helper_process_start`,
//! ADR 0018) — both re-derived from `/proc` on every check rather
//! than trusted from the request, since PID integers are recyclable.
//! `ValidatePeer` is the only path that advances `issued` to
//! `active`; `InspectLiveness` is deliberately read-only.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;

use central_backup::recovery::refusal::RestoreRefusalReason;
use central_foundation::failure::Failure;
use central_infra::authority::{BrokerOutcome, BrokerRequest, BrokerResponse};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable;
use super::migration_launch::verify_peer_process;
use super::protocol::{MAX_REQUEST_LINE, RESTORE_ISSUE_LAUNCH_RPC};
use super::recovery_journal::{JOURNAL_UNAVAILABLE_CODE, RecoveryJournalStore, unavailable};
use super::signing::SigningService;
use super::wire;
use crate::sys::peercred::PeerCred;

const RESTORE_LAUNCH_DIRECTORY: &str = "restore-launch";
const RESTORE_LAUNCH_FILENAME: &str = "current.json";
const RESTORE_LAUNCH_HMAC_DOMAIN: &str = "slice-c-restore-launch-v1";

/// `restoreLaunchDenialPrefix` — the fixed, non-locator prefix
/// `dispatchRestoreIssueLaunch` always writes ahead of a launch
/// denial's cause.
pub(crate) const RESTORE_LAUNCH_DENIAL_PREFIX: &str = "RESTORE_LAUNCH_DENIED: ";

/// `restoreEngineExecutablePath` — the one path a connecting restore
/// engine peer may present in production. It must name the exact same
/// path as the restore launcher's own constant — the two packages
/// intentionally share no common constants package, so this
/// duplication is deliberate and must be kept in lockstep by hand.
pub(crate) const RESTORE_ENGINE_EXECUTABLE_PATH: &str = "/usr/lib/central/central-restore";

/// `RestoreLaunchEvidence` — the launcher-observed child identity,
/// captured immediately after spawn. Nothing here is trusted alone:
/// [`RestoreLaunchStore::issue`] independently re-derives the same
/// facts from `/proc` and requires them to match.
#[derive(Debug, Clone)]
pub struct RestoreLaunchEvidence {
    pub pid: i32,
    pub process_start: String,
    pub executable: String,
    pub mode: String,
    pub expires_at: OffsetDateTime,
}

/// `RestoreLaunchBinding` — the launch-evidence identity a validated
/// peer check yields: just enough to identify which record admitted
/// the peer and under what mode, not the full record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreLaunchBinding {
    pub launch_evidence_id: Uuid,
    pub mode: &'static str,
}

/// `RestoreLaunchLiveness` — what a peerless, read-only inspection of
/// the bound launch record can say. Deliberately not
/// [`RestoreLaunchBinding`]: that value is what a validated peer
/// earned, and nothing here validates a peer.
#[derive(Debug, Clone)]
pub struct RestoreLaunchLiveness {
    pub bound: bool,
    pub launch_evidence_id: Uuid,
    pub mode: String,
    pub engine_pid: i32,
    /// `EngineLive` — the `/proc` re-derivation `ValidatePeer` also
    /// performs: bound PID's resolved executable, kernel start time,
    /// and parent PID all still matching the record.
    pub engine_live: bool,
    pub deadline_passed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreLaunchState {
    Issued,
    Active,
}

impl RestoreLaunchState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Active => "active",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "issued" => Self::Issued,
            "active" => Self::Active,
            _ => return None,
        })
    }
}

/// `validRestoreLaunchMode` — ADR 0034: `import` binds a
/// central-restore import run under the same single-flight pinning;
/// it adds a mode, not a trust mechanism.
fn valid_restore_launch_mode(mode: &str) -> bool {
    mode == "apply" || mode == "resume" || mode == "verify" || mode == "import"
}

/// `restoreLaunchRecord` — the one currently-bound restore engine
/// process identity.
#[derive(Debug, Clone)]
struct RestoreLaunchRecord {
    launch_evidence_id: Uuid,
    mode: String,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    parent_pid: i32,
    process_start: String,
    executable: String,
    helper_executable: String,
    helper_process_start: String,
    deadline: OffsetDateTime,
    created_at: OffsetDateTime,
    state: RestoreLaunchState,
    nonce: String,
    hmac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreLaunchRecordWire {
    launch_evidence_id: Uuid,
    mode: String,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    parent_pid: i32,
    process_start: String,
    executable: String,
    helper_executable: String,
    helper_process_start: String,
    #[serde(with = "wire::rfc3339")]
    deadline: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    created_at: OffsetDateTime,
    state: String,
    nonce: String,
    hmac_sha256: String,
}

fn record_to_wire(record: &RestoreLaunchRecord) -> RestoreLaunchRecordWire {
    RestoreLaunchRecordWire {
        launch_evidence_id: record.launch_evidence_id,
        mode: record.mode.clone(),
        peer_uid: record.peer_uid,
        peer_gid: record.peer_gid,
        peer_pid: record.peer_pid,
        parent_pid: record.parent_pid,
        process_start: record.process_start.clone(),
        executable: record.executable.clone(),
        helper_executable: record.helper_executable.clone(),
        helper_process_start: record.helper_process_start.clone(),
        deadline: record.deadline.to_offset(time::UtcOffset::UTC),
        created_at: record.created_at.to_offset(time::UtcOffset::UTC),
        state: record.state.as_str().to_owned(),
        nonce: record.nonce.clone(),
        hmac_sha256: record.hmac.clone(),
    }
}

fn record_from_wire(wire: &RestoreLaunchRecordWire) -> Result<RestoreLaunchRecord, Failure> {
    let Some(state) = RestoreLaunchState::from_str(&wire.state) else {
        return Err(unavailable());
    };
    Ok(RestoreLaunchRecord {
        launch_evidence_id: wire.launch_evidence_id,
        mode: wire.mode.clone(),
        peer_uid: wire.peer_uid,
        peer_gid: wire.peer_gid,
        peer_pid: wire.peer_pid,
        parent_pid: wire.parent_pid,
        process_start: wire.process_start.clone(),
        executable: wire.executable.clone(),
        helper_executable: wire.helper_executable.clone(),
        helper_process_start: wire.helper_process_start.clone(),
        deadline: wire.deadline,
        created_at: wire.created_at,
        state,
        nonce: wire.nonce.clone(),
        hmac: wire.hmac_sha256.clone(),
    })
}

/// `restoreLaunchRecordPayload` — the canonical HMAC input.
#[derive(Serialize)]
struct RestoreLaunchRecordPayload<'a> {
    launch_evidence_id: String,
    mode: &'a str,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    parent_pid: i32,
    process_start: &'a str,
    executable: &'a str,
    helper_executable: &'a str,
    helper_process_start: &'a str,
    deadline: String,
    created_at: String,
    state: &'a str,
    nonce: &'a str,
}

fn canonical_payload(record: &RestoreLaunchRecord) -> Result<Vec<u8>, Failure> {
    let Some(nonce_bytes) = wire::hex_decode(&record.nonce) else {
        return Err(unavailable());
    };
    if record.launch_evidence_id.is_nil()
        || !valid_restore_launch_mode(&record.mode)
        || record.peer_pid <= 0
        || record.parent_pid <= 0
        || record.process_start.is_empty()
        || record.executable.is_empty()
        || record.helper_executable.is_empty()
        || record.helper_process_start.is_empty()
        || wire::is_go_zero_time(record.deadline)
        || wire::is_go_zero_time(record.created_at)
        || nonce_bytes.len() != 32
    {
        return Err(unavailable());
    }
    serde_json::to_vec(&RestoreLaunchRecordPayload {
        launch_evidence_id: record.launch_evidence_id.to_string(),
        mode: &record.mode,
        peer_uid: record.peer_uid,
        peer_gid: record.peer_gid,
        peer_pid: record.peer_pid,
        parent_pid: record.parent_pid,
        process_start: &record.process_start,
        executable: &record.executable,
        helper_executable: &record.helper_executable,
        helper_process_start: &record.helper_process_start,
        deadline: wire::format_rfc3339_nano(record.deadline.to_offset(time::UtcOffset::UTC)),
        created_at: wire::format_rfc3339_nano(record.created_at.to_offset(time::UtcOffset::UTC)),
        state: record.state.as_str(),
        nonce: &record.nonce,
    })
    .map_err(|_| unavailable())
}

/// `inspectRestoreEngineProcess` — [`verify_peer_process`] plus the
/// parent-PID field this store needs to pin the connecting engine's
/// parent to the helper that launched it.
fn inspect_restore_engine_process(pid: i32) -> Result<(String, String, i32), Failure> {
    let (exe, starttime) = verify_peer_process(pid)?;
    // `read_to_string` reserves capacity from `File::metadata`, whose
    // glibc `fstat` emits `statx` on this toolchain — read via the
    // fd-only `durable` path instead.
    let stat = crate::broker::durable::read_file(std::path::Path::new(&format!("/proc/{pid}/stat")))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|e| Failure::internal(JOURNAL_UNAVAILABLE_CODE, format!("read stat: {e}")))?;
    // Fields after the last `)` — the comm field can contain spaces
    // and parentheses; fields[1] is the parent PID.
    let paren = stat.rfind(')').ok_or_else(unavailable)?;
    let fields: Vec<&str> = stat[paren + 1..].split_whitespace().collect();
    if fields.len() < 2 {
        return Err(unavailable());
    }
    let Ok(ppid) = fields[1].parse::<i32>() else {
        return Err(unavailable());
    };
    Ok((exe, starttime, ppid))
}

/// `helperExecutablePathFromSelf` — the broker resolves its own
/// binary, the identical way `verify_peer_process` resolves any
/// connecting peer's: `central --helper`, `--broker`, and
/// `--sandbox-launcher` are the same installed file, so the broker's
/// own resolved path is the helper's path and the pin is
/// self-verifying against reality rather than a hand-maintained
/// literal.
fn helper_executable_path_from_self() -> Result<String, Failure> {
    let (exe, _) = verify_peer_process(std::process::id() as i32)?;
    Ok(exe)
}

/// `restoreLaunchIssueRequest` — the RPC payload mirror of
/// [`RestoreLaunchEvidence`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreLaunchIssueRequest {
    pub pid: i32,
    pub process_start: String,
    pub executable: String,
    pub mode: String,
    #[serde(with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// `RestoreLaunchStore` — binds the restore engine process identity
/// at launch, from the launcher's own child PID (ADR 0015 Option A).
/// The broker's root peer gate admits on `uid == 0 && gid == 0`
/// alone, which cannot distinguish the restore engine from any other
/// root process; this store is the record that carries the
/// distinction, written by the parent that created the child rather
/// than self-reported by the engine.
pub struct RestoreLaunchStore {
    root: PathBuf,
    signing: Arc<SigningService>,
    journal: Arc<RecoveryJournalStore>,
    /// `executablePath` — the one path a bound engine may run from.
    /// Production composition always sets
    /// [`RESTORE_ENGINE_EXECUTABLE_PATH`]; tests may override on their
    /// own instance (crate-private field, same as upstream's
    /// unexported `executablePath`).
    pub(crate) executable_path: String,
    /// `helperExecutablePath` — the one path a connecting root helper
    /// may run from. Production composition sets it once to the
    /// broker's own resolved executable; a test overrides it
    /// directly. See upstream's SC-DEF-58 note on why self-resolution
    /// is only correct inside the real root helper process.
    pub(crate) helper_executable_path: String,
}

impl RestoreLaunchStore {
    /// `newRestoreLaunchStore` — self-resolved helper identity.
    pub fn new(
        broker_root: &std::path::Path,
        signing: Arc<SigningService>,
        journal: Arc<RecoveryJournalStore>,
    ) -> Result<Self, Failure> {
        Self::new_with_helper_executable(broker_root, signing, journal, "")
    }

    /// `newRestoreLaunchStoreWithHelperExecutable` — the explicit
    /// override for the one case that must not self-resolve
    /// (SC-DEF-58: `broker.NewService` composed inside
    /// `central-restore`'s own process would resolve "self" to the
    /// engine binary, not the helper's).
    pub fn new_with_helper_executable(
        broker_root: &std::path::Path,
        signing: Arc<SigningService>,
        journal: Arc<RecoveryJournalStore>,
        helper_executable_path_override: &str,
    ) -> Result<Self, Failure> {
        let root = broker_root.join(RESTORE_LAUNCH_DIRECTORY);
        durable::mkdir_p(&root, durable::PRIVATE_DIRECTORY_MODE).map_err(|e| {
            Failure::internal(
                JOURNAL_UNAVAILABLE_CODE,
                format!("restore launch store: create root: {e}"),
            )
        })?;
        durable::validate_private_directory(&root, "restore launch root")?;
        let helper_executable_path = if helper_executable_path_override.is_empty() {
            helper_executable_path_from_self()?
        } else {
            helper_executable_path_override.to_owned()
        };
        Ok(Self {
            root,
            signing,
            journal,
            executable_path: RESTORE_ENGINE_EXECUTABLE_PATH.to_owned(),
            helper_executable_path,
        })
    }

    /// `Issue` — binds a freshly started engine process as the one
    /// peer frame 0xc2 will admit, superseding any prior binding whose
    /// process is no longer alive. `helper_pid` is the
    /// SO_PEERCRED-reported PID of the connection submitting this
    /// call — the kernel's own view of who is asking, never a value
    /// the caller writes into the payload.
    ///
    /// A prior record is refused rather than silently bumped if its
    /// process is still alive and still itself — the typed
    /// [`RestoreRefusalReason::StateInvalid`] is the one refusal a
    /// caller can act on, propagated verbatim into the
    /// `RESTORE_LAUNCH_DENIED:` response so the issuer client can
    /// recover it.
    pub fn issue(&self, evidence: &RestoreLaunchEvidence, helper_pid: i32) -> Result<(), Failure> {
        if evidence.pid <= 0
            || evidence.process_start.is_empty()
            || evidence.executable.is_empty()
            || !valid_restore_launch_mode(&evidence.mode)
            || wire::is_go_zero_time(evidence.expires_at)
            || OffsetDateTime::now_utc() >= evidence.expires_at
            || helper_pid <= 0
        {
            return Err(unavailable());
        }
        let Ok((executable, process_start, parent_pid)) =
            inspect_restore_engine_process(evidence.pid)
        else {
            return Err(unavailable());
        };
        if executable != evidence.executable
            || process_start != evidence.process_start
            || executable != self.executable_path
            || parent_pid != helper_pid
        {
            return Err(unavailable());
        }
        // Bind the helper's own identity from /proc too, the same way
        // the engine's was just derived — not from anything the
        // caller wrote into the request.
        let Ok((helper_executable, helper_process_start)) = verify_peer_process(helper_pid) else {
            return Err(unavailable());
        };
        if helper_executable != self.helper_executable_path {
            return Err(unavailable());
        }
        let launch_id = Uuid::now_v7();
        let mut nonce = [0u8; 32];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| unavailable())?;
        let mut record = RestoreLaunchRecord {
            launch_evidence_id: launch_id,
            mode: evidence.mode.clone(),
            peer_uid: 0,
            peer_gid: 0,
            peer_pid: evidence.pid,
            parent_pid,
            process_start,
            executable,
            helper_executable,
            helper_process_start,
            deadline: evidence.expires_at.to_offset(time::UtcOffset::UTC),
            created_at: OffsetDateTime::now_utc(),
            state: RestoreLaunchState::Issued,
            nonce: wire::hex_encode(&nonce),
            hmac: String::new(),
        };
        if self.sign_record(&mut record).is_err() {
            return Err(unavailable());
        }
        let lock = self.journal.open_lock(&self.path())?;
        let result = (|| -> Result<(), Failure> {
            if let Ok(existing) = self.read()
                && let Ok((exe, start, _)) = inspect_restore_engine_process(existing.peer_pid)
                && exe == existing.executable
                && start == existing.process_start
            {
                // The previously bound engine is still alive and
                // still itself: refuse to bump it — the one Issue
                // refusal a caller can act on, so it carries the
                // typed closed vocabulary rather than the generic
                // sentinel.
                return Err(RestoreRefusalReason::StateInvalid.into_failure());
            }
            self.journal
                .replace_json(&self.path(), &record_to_wire(&record))
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `ValidatePeer` — the daemon-side check ADR 0015 authorizes: a
    /// connecting peer is admitted only if it is the exact process
    /// `Issue` bound, not merely any root process. Advances `issued`
    /// → `active` only after the full identity check succeeds.
    pub fn validate_peer(&self, peer: &PeerCred) -> Result<RestoreLaunchBinding, Failure> {
        if peer.uid.as_raw() != 0 || peer.gid.as_raw() != 0 || peer.pid.as_raw_pid() <= 0 {
            return Err(unavailable());
        }
        let lock = self.journal.open_lock(&self.path())?;
        let result = (|| -> Result<RestoreLaunchBinding, Failure> {
            let mut record = self.read()?;
            if record.peer_pid != peer.pid.as_raw_pid()
                || OffsetDateTime::now_utc() >= record.deadline
            {
                return Err(unavailable());
            }
            let Ok((executable, process_start, parent_pid)) =
                inspect_restore_engine_process(peer.pid.as_raw_pid())
            else {
                return Err(unavailable());
            };
            if executable != record.executable
                || process_start != record.process_start
                || parent_pid != record.parent_pid
            {
                return Err(unavailable());
            }
            if record.state == RestoreLaunchState::Issued {
                record.state = RestoreLaunchState::Active;
                if self.sign_record(&mut record).is_err()
                    || self
                        .journal
                        .replace_json(&self.path(), &record_to_wire(&record))
                        .is_err()
                {
                    return Err(unavailable());
                }
            }
            Ok(RestoreLaunchBinding {
                launch_evidence_id: record.launch_evidence_id,
                mode: static_mode(&record.mode)?,
            })
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `ValidateHelperPeer` — admits the root helper that issued the
    /// currently bound restore launch record, rather than any root
    /// process that happens to share its (in principle recyclable)
    /// `parent_pid`. Checks the connecting helper against
    /// `parent_pid`/`helper_executable`/`helper_process_start`,
    /// re-derived from `/proc` exactly as `inspect_restore_engine_process`
    /// does for the engine.
    pub fn validate_helper_peer(&self, peer: &PeerCred) -> Result<RestoreLaunchBinding, Failure> {
        if peer.uid.as_raw() != 0 || peer.gid.as_raw() != 0 || peer.pid.as_raw_pid() <= 0 {
            return Err(unavailable());
        }
        let lock = self.journal.open_lock(&self.path())?;
        let result = (|| -> Result<RestoreLaunchBinding, Failure> {
            let record = self.read()?;
            if record.parent_pid != peer.pid.as_raw_pid()
                || OffsetDateTime::now_utc() >= record.deadline
            {
                return Err(unavailable());
            }
            let Ok((executable, process_start)) = verify_peer_process(peer.pid.as_raw_pid()) else {
                return Err(unavailable());
            };
            if executable != record.helper_executable
                || process_start != record.helper_process_start
            {
                return Err(unavailable());
            }
            Ok(RestoreLaunchBinding {
                launch_evidence_id: record.launch_evidence_id,
                mode: static_mode(&record.mode)?,
            })
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `InspectLiveness` — the peerless, read-only liveness reader.
    /// Absence is answered before the lock is taken, from the record
    /// path rather than from `read`'s error value: `read` collapses
    /// "no such file" and "this record is corrupt" into one sentinel,
    /// and those are exactly the two answers this reader must not
    /// confuse. Never advances `issued` to `active`.
    pub fn inspect_liveness(&self, now: OffsetDateTime) -> Result<RestoreLaunchLiveness, Failure> {
        if wire::is_go_zero_time(now) {
            return Err(unavailable());
        }
        match durable::lstat(&self.path()) {
            Err(e) if e == rustix::io::Errno::NOENT => {
                return Ok(RestoreLaunchLiveness {
                    bound: false,
                    launch_evidence_id: Uuid::nil(),
                    mode: String::new(),
                    engine_pid: 0,
                    engine_live: false,
                    deadline_passed: false,
                });
            }
            Err(_) => return Err(unavailable()),
            Ok(_) => {}
        }
        let lock = self.journal.open_lock(&self.path())?;
        let result = (|| -> Result<RestoreLaunchLiveness, Failure> {
            let record = self.read()?;
            let mut liveness = RestoreLaunchLiveness {
                bound: true,
                launch_evidence_id: record.launch_evidence_id,
                mode: record.mode.clone(),
                engine_pid: record.peer_pid,
                engine_live: false,
                deadline_passed: now >= record.deadline,
            };
            if let Ok((executable, process_start, parent_pid)) =
                inspect_restore_engine_process(record.peer_pid)
            {
                liveness.engine_live = executable == record.executable
                    && process_start == record.process_start
                    && parent_pid == record.parent_pid;
            }
            Ok(liveness)
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `s.read` — strict decode + structural validation + the
    /// broker-HMAC over the canonical payload.
    fn read(&self) -> Result<RestoreLaunchRecord, Failure> {
        let wire_record: RestoreLaunchRecordWire =
            super::recovery_journal::read_private_json(&self.path())?;
        let record = record_from_wire(&wire_record)?;
        if record.launch_evidence_id.is_nil()
            || record.peer_uid != 0
            || record.peer_gid != 0
            || record.peer_pid <= 0
            || record.parent_pid <= 0
            || record.process_start.is_empty()
            || record.executable != self.executable_path
            || !valid_restore_launch_mode(&record.mode)
            || record.helper_process_start.is_empty()
            || record.helper_executable != self.helper_executable_path
            || wire::is_go_zero_time(record.deadline)
            || wire::is_go_zero_time(record.created_at)
        {
            return Err(unavailable());
        }
        let payload = canonical_payload(&record)?;
        let want = self
            .signing
            .fingerprint(RESTORE_LAUNCH_HMAC_DOMAIN, &payload);
        if !wire::hmac_equal(record.hmac.as_bytes(), want.as_bytes()) {
            return Err(unavailable());
        }
        Ok(record)
    }

    /// `s.signRecord` — HMAC over the canonical payload.
    fn sign_record(&self, record: &mut RestoreLaunchRecord) -> Result<(), Failure> {
        let payload = canonical_payload(record)?;
        record.hmac = self
            .signing
            .fingerprint(RESTORE_LAUNCH_HMAC_DOMAIN, &payload);
        Ok(())
    }

    fn path(&self) -> PathBuf {
        self.root.join(RESTORE_LAUNCH_FILENAME)
    }
}

/// `static_mode` — the record's mode as a `&'static str`, keeping
/// [`RestoreLaunchBinding`] allocation-free like the upstream struct.
fn static_mode(mode: &str) -> Result<&'static str, Failure> {
    match mode {
        "apply" => Ok("apply"),
        "resume" => Ok("resume"),
        "verify" => Ok("verify"),
        "import" => Ok("import"),
        _ => Err(unavailable()),
    }
}

// ---------------------------------------------------------------------------
// RestoreLaunchIssuer — the client half (`restore_launch_issuer.go`).
// ---------------------------------------------------------------------------

/// `RestoreLaunchIssuer` submits the launcher-observed child identity
/// to the separately running protected broker immediately after the
/// launcher's spawn returns, so the binding ADR 0015 requires exists
/// before the engine can make its first daemon call — never
/// established by that call itself.
pub struct RestoreLaunchIssuer {
    socket_path: String,
}

/// `RestoreLaunchClientEvidence` mirrors [`RestoreLaunchEvidence`]
/// across the wire.
#[derive(Debug, Clone)]
pub struct RestoreLaunchClientEvidence {
    pub pid: i32,
    pub process_start: String,
    pub executable: String,
    pub mode: String,
    pub expires_at: OffsetDateTime,
}

fn issuer_err(msg: impl Into<String>) -> Failure {
    Failure::internal(
        "broker_restore_launch_client",
        format!("broker restore launch: {}", msg.into()),
    )
}

impl RestoreLaunchIssuer {
    /// `NewRestoreLaunchIssuer`.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// `IssueRestoreLaunch` — one JSON-line `restore_issue_launch`
    /// request; a non-success outcome carries the broker's denial
    /// message through [`restore_launch_denial_reason`], which
    /// recovers a typed [`RestoreRefusalReason`] only when the denial
    /// names a recognized one.
    ///
    /// Upstream performs a bare `unix` dial — no peer credential
    /// check on this path (the caller is the root helper whose own
    /// identity `Issue` re-derives). Mirrored here.
    pub fn issue_restore_launch(
        &self,
        evidence: &RestoreLaunchClientEvidence,
    ) -> Result<(), Failure> {
        if self.socket_path.is_empty()
            || evidence.pid <= 0
            || evidence.process_start.is_empty()
            || evidence.executable.is_empty()
            || !valid_restore_launch_mode(&evidence.mode)
            || wire::is_go_zero_time(evidence.expires_at)
        {
            return Err(issuer_err("incomplete child identity"));
        }
        let payload_raw: Box<RawValue> = serde_json::from_str(
            &serde_json::to_string(&RestoreLaunchIssueRequest {
                pid: evidence.pid,
                process_start: evidence.process_start.clone(),
                executable: evidence.executable.clone(),
                mode: evidence.mode.clone(),
                expires_at: evidence.expires_at.to_offset(time::UtcOffset::UTC),
            })
            .map_err(|e| issuer_err(format!("encode request: {e}")))?,
        )
        .map_err(|e| issuer_err(format!("encode request: {e}")))?;
        let request = BrokerRequest {
            operation_id: format!("restore-launch:{}", evidence.mode),
            purpose: RESTORE_ISSUE_LAUNCH_RPC.to_owned(),
            session_token: String::new(),
            payload: Some(BTreeMap::from([("request".to_owned(), payload_raw)])),
        };
        let mut conn =
            UnixStream::connect(&self.socket_path).map_err(|e| issuer_err(format!("dial: {e}")))?;
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .map_err(|e| issuer_err(format!("dial: {e}")))?;
        conn.set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .map_err(|e| issuer_err(format!("dial: {e}")))?;
        let mut encoded = serde_json::to_vec(&request)
            .map_err(|e| issuer_err(format!("encode broker request: {e}")))?;
        encoded.push(b'\n');
        conn.write_all(&encoded)
            .map_err(|e| issuer_err(format!("write request: {e}")))?;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while line.len() <= MAX_REQUEST_LINE {
            match conn.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    line.push(byte[0]);
                }
                Err(e) => return Err(issuer_err(format!("read response: {e}"))),
            }
        }
        let response: BrokerResponse =
            serde_json::from_slice(&line).map_err(|e| issuer_err(format!("read response: {e}")))?;
        if response.outcome != BrokerOutcome::Success {
            return Err(restore_launch_denial_reason(&response.evidence.message));
        }
        Ok(())
    }
}

/// `restoreLaunchDenialReason` — recovers a typed, sanitized
/// [`RestoreRefusalReason`] from the broker's denial message when the
/// launch was refused for a cause `RestoreLaunchStore::issue`
/// classifies that specifically — today, only "a prior binding is
/// still alive" (ADR 0015's single-flight restriction). Any other
/// denial content still returns the generic denial: additive to the
/// fail-closed default, never a relaxation.
fn restore_launch_denial_reason(message: &str) -> Failure {
    let Some(reason_text) = message.strip_prefix(RESTORE_LAUNCH_DENIAL_PREFIX) else {
        return Failure::denied(
            "broker_restore_launch_denied",
            "broker restore launch: denied",
        );
    };
    match RestoreRefusalReason::from_wire(reason_text) {
        Some(reason) => reason.into_failure(),
        None => Failure::denied(
            "broker_restore_launch_denied",
            "broker restore launch: denied",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Child, Command};
    use std::sync::Arc;

    use central_backup::recovery::refusal::{RestoreRefusalReason, sanitize_restore_refusal_cause};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::broker::protected_file::ProtectedFileBackend;
    use crate::broker::testutil::TempDir;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    struct Env {
        _dir: TempDir,
        store: RestoreLaunchStore,
    }

    fn env() -> Env {
        let dir = TempDir::new("restore-launch");
        let backend = ProtectedFileBackend::new(dir.join("protected"));
        let signing = Arc::new(SigningService::new());
        let journal = Arc::new(RecoveryJournalStore::new(&dir, signing.clone(), backend).unwrap());
        let store = RestoreLaunchStore::new(&dir, signing, journal).unwrap();
        Env { _dir: dir, store }
    }

    /// A live "engine" child of this test process.
    fn spawn_engine() -> (Child, i32, String, String) {
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let (executable, process_start) = verify_peer_process(pid).unwrap();
        (child, pid, executable, process_start)
    }

    fn evidence(pid: i32, executable: &str, process_start: &str) -> RestoreLaunchEvidence {
        RestoreLaunchEvidence {
            pid,
            process_start: process_start.to_owned(),
            executable: executable.to_owned(),
            mode: "apply".to_owned(),
            expires_at: now() + Duration::seconds(60),
        }
    }

    fn cred(pid: i32, uid: u32, gid: u32) -> PeerCred {
        PeerCred {
            pid: rustix::process::Pid::from_raw(pid).unwrap(),
            uid: rustix::process::Uid::from_raw(uid),
            gid: rustix::process::Gid::from_raw(gid),
        }
    }

    #[test]
    fn issue_binds_single_flight_and_liveness_tracks_death() {
        let mut env = env();
        let (mut child, pid, exe, start) = spawn_engine();
        env.store.executable_path = exe.clone();
        let helper = std::process::id() as i32;
        let ev = evidence(pid, &exe, &start);
        env.store.issue(&ev, helper).unwrap();

        let live = env.store.inspect_liveness(now()).unwrap();
        assert!(live.bound && live.engine_live);
        assert_eq!(live.engine_pid, pid);
        assert!(!live.deadline_passed);

        // Single-flight: a live, still-itself engine cannot be bumped —
        // the typed StateInvalid refusal, not the generic sentinel.
        let err = env.store.issue(&ev, helper).unwrap_err();
        assert_eq!(
            sanitize_restore_refusal_cause(&err),
            Some(RestoreRefusalReason::StateInvalid)
        );

        // After the engine dies, liveness reports bound-but-dead and a
        // fresh engine may rebind.
        child.kill().unwrap();
        child.wait().unwrap();
        let live = env.store.inspect_liveness(now()).unwrap();
        assert!(live.bound && !live.engine_live);

        let (mut child2, pid2, _exe2, start2) = spawn_engine();
        let ev2 = evidence(pid2, &exe, &start2);
        env.store.issue(&ev2, helper).unwrap();
        let live = env.store.inspect_liveness(now()).unwrap();
        assert!(live.bound && live.engine_live && live.engine_pid == pid2);
        child2.kill().unwrap();
        child2.wait().unwrap();
    }

    #[test]
    fn issue_refuses_foreign_helper_and_fabricated_identity() {
        let mut env = env();
        let (_child, pid, exe, start) = spawn_engine();
        env.store.executable_path = exe.clone();
        let helper = std::process::id() as i32;

        // The "helper" pid is not the engine's actual parent.
        let ev = evidence(pid, &exe, &start);
        assert!(env.store.issue(&ev, pid).is_err());
        // Fabricated process start fails the /proc re-derivation.
        let ev = evidence(pid, &exe, "not-a-start-time");
        assert!(env.store.issue(&ev, helper).is_err());
        // Evidence claiming a different executable fails too.
        let ev = evidence(pid, "/bin/sh", &start);
        assert!(env.store.issue(&ev, helper).is_err());
        // A deadline in the past is refused before identity work.
        let mut ev = evidence(pid, &exe, &start);
        ev.expires_at = now() - Duration::seconds(1);
        assert!(env.store.issue(&ev, helper).is_err());
        // An engine whose path is not the pinned engine path fails.
        env.store.executable_path = "/usr/lib/central/central-restore".to_owned();
        let ev = evidence(pid, &exe, &start);
        assert!(env.store.issue(&ev, helper).is_err());
    }

    #[test]
    fn peerless_liveness_and_foreign_peers_fail_closed() {
        let mut env = env();
        // No record: bound=false, not an error.
        let live = env.store.inspect_liveness(now()).unwrap();
        assert!(!live.bound && !live.engine_live);
        assert!(env.store.validate_peer(&cred(1234, 0, 0)).is_err());
        assert!(env.store.validate_helper_peer(&cred(1234, 0, 0)).is_err());

        let (mut child, pid, exe, start) = spawn_engine();
        env.store.executable_path = exe.clone();
        let helper = std::process::id() as i32;
        env.store
            .issue(&evidence(pid, &exe, &start), helper)
            .unwrap();

        // A peer that is not the recorded engine pid fails closed.
        assert!(
            env.store
                .validate_peer(&cred(std::process::id() as i32, 0, 0))
                .is_err()
        );
        // A peer that is not the recorded helper fails closed.
        assert!(env.store.validate_helper_peer(&cred(pid, 0, 0)).is_err());
        // Non-root peers never reach the record checks.
        let nonroot = cred(pid, rustix::process::geteuid().as_raw().max(1), 1);
        assert!(env.store.validate_peer(&nonroot).is_err());

        child.kill().unwrap();
        child.wait().unwrap();
        // After death, peer validation fails closed too — the bound
        // identity cannot resolve in /proc anymore.
        assert!(env.store.validate_peer(&cred(pid, 0, 0)).is_err());
        let live = env.store.inspect_liveness(now()).unwrap();
        assert!(live.bound && !live.engine_live);
    }
}
