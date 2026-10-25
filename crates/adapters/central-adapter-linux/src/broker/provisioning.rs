//! `provisioning.go` + `provisioning_store.go` — the broker-protected
//! provisioning-record store: one record per target under
//! `operator-state/<fingerprint>.json`, create-exclusive install,
//! compare-and-swap by revision, and a journaled
//! `provisioning-state-transition` intent committed before every
//! mutation.
//!
//! Wire fidelity: `ProvisioningRecord`/`ReplaceProvisioningRecordRequest`/
//! `ProvisioningJournalIntent` serialize exactly as Go's untagged
//! structs — PascalCase field names — because upstream `json.Marshal`
//! sees exported names. `ProvisioningJournalEntry` carries upstream's
//! own snake_case tags.

use std::fs;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use central_backup::domain::{SessionBinding, TargetIdentity};
use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable::{PRIVATE_DIRECTORY_MODE, sync_dir};
use super::journal::Journal;
use super::wire::{hex_encode, is_go_zero_time, rfc3339};

fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("broker_provisioning", msg.into())
}
fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("broker_provisioning", msg.into())
}

/// `backup.ErrRecordAbsent` — the absent-record sentinel the read path
/// and the migration RPC's `PROVISIONING_RECORD_ABSENT` code key off.
pub const ERR_RECORD_ABSENT: &str = "provisioning record absent";

/// `ProvRecordInitializing` / `ProvRecordReady` /
/// `ProvRecordAbsent`-deletion marker.
pub const PROV_RECORD_INITIALIZING: &str = "initializing";
pub const PROV_RECORD_READY: &str = "ready";
/// The deletion target state `validateTransition` admits unconditionally.
pub const PROV_RECORD_ABSENT: &str = "absent";

/// `PhaseRecorded` … `PhaseCandidateActive` — the four provisioning
/// phases.
pub const PHASE_RECORDED: &str = "recorded";
pub const PHASE_CANDIDATE_STAGED: &str = "candidate_staged";
pub const PHASE_BASELINE_INSTALLED: &str = "baseline_installed";
pub const PHASE_CANDIDATE_ACTIVE: &str = "candidate_active";

// ---------------------------------------------------------------------------
// Wire types — Go's untagged (PascalCase) JSON shape
// ---------------------------------------------------------------------------

/// `backup.TargetIdentity` wire form — upstream has no JSON tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetIdentityWire {
    /// `SystemID`.
    #[serde(rename = "SystemID")]
    pub system_id: String,
    /// `DatabaseOID`.
    #[serde(rename = "DatabaseOID")]
    pub database_oid: String,
    /// `Database`.
    #[serde(rename = "Database")]
    pub database: String,
    /// `ConfigHash`.
    #[serde(rename = "ConfigHash")]
    pub config_hash: String,
    /// `Epoch`.
    #[serde(rename = "Epoch")]
    pub epoch: u64,
}

impl From<&TargetIdentity> for TargetIdentityWire {
    fn from(t: &TargetIdentity) -> Self {
        Self {
            system_id: t.system_id.clone(),
            database_oid: t.database_oid.clone(),
            database: t.database.clone(),
            config_hash: t.config_hash.clone(),
            epoch: t.epoch,
        }
    }
}

impl From<&TargetIdentityWire> for TargetIdentity {
    fn from(t: &TargetIdentityWire) -> Self {
        Self {
            system_id: t.system_id.clone(),
            database_oid: t.database_oid.clone(),
            database: t.database.clone(),
            config_hash: t.config_hash.clone(),
            epoch: t.epoch,
        }
    }
}

/// `backup.SessionBinding` wire form — `LockIdentities` is a Go array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBindingWire {
    /// `BackendPID`.
    #[serde(rename = "BackendPID")]
    pub backend_pid: i32,
    /// `BackendStart`.
    #[serde(rename = "BackendStart")]
    pub backend_start: String,
    /// `BootID`.
    #[serde(rename = "BootID")]
    pub boot_id: String,
    /// `LockIdentities` — `[3]string` upstream; an empty/missing list
    /// decodes as the zero value.
    #[serde(rename = "LockIdentities", default)]
    pub lock_identities: Vec<String>,
}

impl From<&SessionBinding> for SessionBindingWire {
    fn from(s: &SessionBinding) -> Self {
        // Go `[3]string` always marshals three elements; absent
        // positions marshal as "".
        let mut ids = s.lock_identities.clone();
        ids.resize(3, String::new());
        ids.truncate(3);
        Self {
            backend_pid: s.backend_pid,
            backend_start: s.backend_start.clone(),
            boot_id: s.boot_id.clone(),
            lock_identities: ids,
        }
    }
}

impl From<&SessionBindingWire> for SessionBinding {
    fn from(s: &SessionBindingWire) -> Self {
        Self {
            backend_pid: s.backend_pid,
            backend_start: s.backend_start.clone(),
            boot_id: s.boot_id.clone(),
            lock_identities: s.lock_identities.clone(),
        }
    }
}

/// `ProvisioningRecord` — one durable provisioning record per target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvisioningRecord {
    /// `Target`.
    #[serde(rename = "Target")]
    pub target: TargetIdentityWire,
    /// `OperationID`.
    #[serde(rename = "OperationID")]
    pub operation_id: Uuid,
    /// `State`.
    #[serde(rename = "State")]
    pub state: String,
    /// `Phase`.
    #[serde(rename = "Phase")]
    pub phase: String,
    /// `CandidateID`.
    #[serde(rename = "CandidateID")]
    pub candidate_id: Uuid,
    /// `CandidateDigest`.
    #[serde(rename = "CandidateDigest")]
    pub candidate_digest: String,
    /// `BaselineDigest`.
    #[serde(rename = "BaselineDigest")]
    pub baseline_digest: String,
    /// `EpochZeroMarkers` — `null`/`[]` per Go's slice encoding.
    #[serde(rename = "EpochZeroMarkers")]
    pub epoch_zero_markers: Option<Vec<String>>,
    /// `SessionBinding`.
    #[serde(rename = "SessionBinding")]
    pub session_binding: SessionBindingWire,
    /// `Revision`.
    #[serde(rename = "Revision")]
    pub revision: u64,
    /// `CreatedAt`.
    #[serde(rename = "CreatedAt", with = "super::wire::rfc3339")]
    pub created_at: OffsetDateTime,
    /// `UpdatedAt`.
    #[serde(rename = "UpdatedAt", with = "super::wire::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl ProvisioningRecord {
    /// The Go zero value — the placeholder `readCurrent` returns beside
    /// `absent=true`; never stored.
    pub(crate) fn absent_placeholder() -> Self {
        Self {
            target: TargetIdentityWire {
                system_id: String::new(),
                database_oid: String::new(),
                database: String::new(),
                config_hash: String::new(),
                epoch: 0,
            },
            operation_id: Uuid::nil(),
            state: String::new(),
            phase: String::new(),
            candidate_id: Uuid::nil(),
            candidate_digest: String::new(),
            baseline_digest: String::new(),
            epoch_zero_markers: None,
            session_binding: SessionBindingWire {
                backend_pid: 0,
                backend_start: String::new(),
                boot_id: String::new(),
                lock_identities: Vec::new(),
            },
            revision: 0,
            created_at: super::wire::GO_ZERO_TIME,
            updated_at: super::wire::GO_ZERO_TIME,
        }
    }
}

/// `ProvisioningJournalIntent` — the transition intent journaled before
/// a mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningJournalIntent {
    /// `OperationID`.
    #[serde(rename = "OperationID")]
    pub operation_id: Uuid,
    /// `TargetFingerprint`.
    #[serde(rename = "TargetFingerprint")]
    pub target_fingerprint: String,
    /// `PreviousState`.
    #[serde(rename = "PreviousState")]
    pub previous_state: String,
    /// `PreviousPhase`.
    #[serde(rename = "PreviousPhase")]
    pub previous_phase: String,
    /// `NextState`.
    #[serde(rename = "NextState")]
    pub next_state: String,
    /// `NextPhase`.
    #[serde(rename = "NextPhase")]
    pub next_phase: String,
    /// `Reason`.
    #[serde(rename = "Reason")]
    pub reason: String,
}

/// `ReplaceProvisioningRecordRequest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplaceProvisioningRecordRequest {
    /// `Target`.
    #[serde(rename = "Target")]
    pub target: TargetIdentityWire,
    /// `ExpectedRevision`.
    #[serde(rename = "ExpectedRevision")]
    pub expected_revision: u64,
    /// `Next`.
    #[serde(rename = "Next")]
    pub next: ProvisioningRecord,
    /// `JournalIntent`.
    #[serde(rename = "JournalIntent")]
    pub journal_intent: ProvisioningJournalIntent,
}

/// `ProvisioningJournalEntry` — upstream's snake_case tags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningJournalEntry {
    /// `target_fingerprint`.
    pub target_fingerprint: String,
    /// `operation_id`.
    pub operation_id: String,
    /// `previous_state`.
    pub previous_state: String,
    /// `previous_phase`.
    pub previous_phase: String,
    /// `next_state`.
    pub next_state: String,
    /// `next_phase`.
    pub next_phase: String,
    /// `reason`.
    pub reason: String,
    /// `recorded_at`.
    #[serde(with = "rfc3339")]
    pub recorded_at: OffsetDateTime,
}

/// `TargetFingerprint` — SHA-256 over
/// `system_id:database_oid:database:config_hash:epoch`, hex.
#[must_use]
pub fn target_fingerprint(t: &TargetIdentity) -> String {
    let mut h = sha2::Sha256::new();
    h.update(t.system_id.as_bytes());
    h.update(b":");
    h.update(t.database_oid.as_bytes());
    h.update(b":");
    h.update(t.database.as_bytes());
    h.update(b":");
    h.update(t.config_hash.as_bytes());
    h.update(b":");
    h.update(t.epoch.to_string().as_bytes());
    hex_encode(&h.finalize())
}

/// `provisioningStore` — one record file per target fingerprint under
/// `root/operator-state`.
pub struct ProvisioningStore {
    root_path: PathBuf,
    journal: Option<std::sync::Arc<Journal>>,
}

impl ProvisioningStore {
    /// `NewProvisioningStore` — records under `root/operator-state`,
    /// transitions journaled through `journal` (optional, as upstream's
    /// nil-journal seam allows).
    #[must_use]
    pub fn new(root_path: PathBuf, journal: Option<std::sync::Arc<Journal>>) -> Self {
        Self { root_path, journal }
    }

    fn record_path(&self, target: &TargetIdentity) -> PathBuf {
        self.root_path
            .join("operator-state")
            .join(format!("{}.json", target_fingerprint(target)))
    }

    /// `ReadProvisioningRecord` — absent is the `ERR_RECORD_ABSENT`
    /// sentinel failure (`not_found` kind).
    ///
    /// # Errors
    /// `broker_provisioning` — `not_found` when absent; `invalid` when
    /// corrupt; `internal` on I/O failure.
    pub fn read_provisioning_record(
        &self,
        target: &TargetIdentity,
    ) -> Result<ProvisioningRecord, Failure> {
        self.read_current(&self.record_path(target))
            .and_then(|(rec, absent)| {
                if absent {
                    Err(Failure::not_found(
                        "broker_provisioning",
                        format!("{ERR_RECORD_ABSENT}: record file is absent"),
                    ))
                } else {
                    Ok(rec)
                }
            })
    }

    /// `CreateProvisioningRecord` — the caller's `record` is normalized:
    /// `Target`, `initializing/recorded`, `revision=1`, timestamps now,
    /// and a UUIDv7 operation when unset. Written `O_EXCL` — an
    /// existing record is a denial, never a clobber.
    ///
    /// # Errors
    /// `broker_provisioning` — `denied` when the record already exists;
    /// `internal` on durable-write or journal failure.
    pub fn create_provisioning_record(
        &self,
        target: &TargetIdentity,
        mut record: ProvisioningRecord,
    ) -> Result<ProvisioningRecord, Failure> {
        let path = self.record_path(target);
        let now = OffsetDateTime::now_utc();
        record.target = TargetIdentityWire::from(target);
        record.state = PROV_RECORD_INITIALIZING.into();
        record.phase = PHASE_RECORDED.into();
        record.revision = 1;
        record.created_at = now;
        record.updated_at = now;
        if record.operation_id.is_nil() {
            record.operation_id = Uuid::now_v7();
        }
        let intent = ProvisioningJournalIntent {
            operation_id: record.operation_id,
            target_fingerprint: target_fingerprint(target),
            previous_state: String::new(),
            previous_phase: String::new(),
            next_state: record.state.clone(),
            next_phase: record.phase.clone(),
            reason: "create_provisioning_record".into(),
        };
        write_new_exclusive(&path, &record)?;
        self.append_journal_intent(&intent)?;
        Ok(record)
    }

    /// `ReplaceProvisioningRecord` — compare-and-swap: the record must
    /// exist, `expected_revision` must match, the transition must be
    /// legal. The journal intent commits before the mutation.
    ///
    /// # Errors
    /// `broker_provisioning` denials on every CAS violation;
    /// `internal` on durable-write or journal failure.
    pub fn replace_provisioning_record(
        &self,
        req: &ReplaceProvisioningRecordRequest,
    ) -> Result<ProvisioningRecord, Failure> {
        let path = self.record_path(&TargetIdentity::from(&req.target));
        let (current, absent) = self.read_current(&path).map_err(|e| {
            Failure::denied(
                "broker_provisioning",
                format!("provisioning: CAS denied: read current: {}", e.message()),
            )
        })?;
        if absent {
            return Err(denied(
                "provisioning: CAS denied: record is absent, cannot replace",
            ));
        }
        if current.revision != req.expected_revision {
            return Err(denied(format!(
                "provisioning: CAS denied: expected revision {}, current {}",
                req.expected_revision, current.revision
            )));
        }
        validate_transition(
            &current.state,
            &current.phase,
            &req.next.state,
            &req.next.phase,
        )
        .map_err(|e| denied(format!("provisioning: CAS denied: {}", e.message())))?;
        self.append_journal_intent(&req.journal_intent)
            .map_err(|e| {
                denied(format!(
                    "provisioning: CAS denied: journal: {}",
                    e.message()
                ))
            })?;

        let mut next = req.next.clone();
        next.revision = current.revision + 1;
        next.created_at = current.created_at;
        if is_go_zero_time(next.created_at) {
            next.created_at = OffsetDateTime::now_utc();
        }
        next.updated_at = OffsetDateTime::now_utc();

        write_atomic(&path, &next)
            .map_err(|e| denied(format!("provisioning: CAS denied: write: {}", e.message())))?;
        Ok(next)
    }

    /// `DeleteProvisioningRecord` — absent is a no-op.
    ///
    /// # Errors
    /// `broker_provisioning` on the removal or dir-sync failure.
    pub fn delete_provisioning_record(&self, target: &TargetIdentity) -> Result<(), Failure> {
        let path = self.record_path(target);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(Failure::internal(
                    "broker_provisioning",
                    format!("provisioning: delete record: {e}"),
                ));
            }
        }
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        if dir.exists() {
            sync_dir(dir)?;
        }
        Ok(())
    }

    /// `readCurrent` — `(record, absent)`: `ENOENT` is the absent
    /// sentinel, not an error; corruption is.
    fn read_current(&self, path: &Path) -> Result<(ProvisioningRecord, bool), Failure> {
        match fs::read(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok((ProvisioningRecord::absent_placeholder(), true))
            }
            Err(e) => Err(Failure::internal(
                "broker_provisioning",
                format!("provisioning: read record: {e}"),
            )),
            Ok(data) => {
                let rec: ProvisioningRecord = serde_json::from_slice(&data).map_err(|e| {
                    Failure::internal(
                        "broker_provisioning",
                        format!("provisioning: decode record (corrupt): {e}"),
                    )
                })?;
                Ok((rec, false))
            }
        }
    }

    /// `appendJournalIntent` — one `provisioning-state-transition`
    /// committed record under stream `provisioning-<fingerprint>`.
    fn append_journal_intent(&self, intent: &ProvisioningJournalIntent) -> Result<(), Failure> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let stream_id = format!("provisioning-{}", intent.target_fingerprint);
        let payload = ProvisioningJournalEntry {
            target_fingerprint: intent.target_fingerprint.clone(),
            operation_id: intent.operation_id.to_string(),
            previous_state: intent.previous_state.clone(),
            previous_phase: intent.previous_phase.clone(),
            next_state: intent.next_state.clone(),
            next_phase: intent.next_phase.clone(),
            reason: intent.reason.clone(),
            recorded_at: OffsetDateTime::now_utc(),
        };
        let raw = serde_json::to_vec(&payload).map_err(|e| {
            Failure::internal("broker_provisioning", format!("marshal journal entry: {e}"))
        })?;
        // `json.RawMessage` passthrough: the journal hashes and persists
        // exactly these marshaled bytes — capture them, don't re-parse
        // into a canonicalizing `Value`.
        let raw_payload: Box<serde_json::value::RawValue> =
            serde_json::from_slice(&raw).map_err(|e| {
                Failure::internal("broker_provisioning", format!("marshal journal entry: {e}"))
            })?;
        let mut journal_payload = central_infra::authority::AuthorityTransitionPayload {
            schema_version: "central.authority-transition/v1".into(),
            stream_id: stream_id.clone(),
            sequence_num: 0,
            phase: String::new(),
            operation: "provisioning-state-transition".into(),
            instance_id: String::new(),
            binding_id: String::new(),
            launch_id: String::new(),
            nonce: String::new(),
            payload: Some(raw_payload),
            payload_digest: String::new(),
            payload_bytes: 0,
            prior_digest: String::new(),
            broker_key_ver: String::new(),
            hmac: String::new(),
            signature: String::new(),
            signed_at: String::new(),
        };
        let _receipt = journal.append_committed(&stream_id, &mut journal_payload)?;
        Ok(())
    }
}

/// `writeNewExclusive` — `O_WRONLY|O_CREATE|O_EXCL` at `0400`, write,
/// fsync, dir-sync.
fn write_new_exclusive(path: &Path, record: &ProvisioningRecord) -> Result<(), Failure> {
    let data = serde_json::to_vec(record)
        .map_err(|e| Failure::internal("broker_provisioning", format!("marshal: {e}")))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)
        .map_err(|e| Failure::internal("broker_provisioning", format!("mkdir: {e}")))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
        .map_err(|e| Failure::internal("broker_provisioning", format!("mkdir: {e}")))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                denied("provisioning: create denied: record already exists")
            } else {
                Failure::internal(
                    "broker_provisioning",
                    format!("provisioning: create: write: {e}"),
                )
            }
        })?;
    let write_result = {
        use std::io::Write as _;
        file.write_all(&data)
            .and_then(|()| file.sync_all())
            .map_err(|e| Failure::internal("broker_provisioning", format!("write record: {e}")))
    };
    drop(file);
    if write_result.is_err() {
        let _ = fs::remove_file(path);
        return write_result;
    }
    sync_dir(dir)
}

/// `writeAtomic` — `path + ".tmp"` `0400`, fsync, rename, dir-sync.
fn write_atomic(path: &Path, record: &ProvisioningRecord) -> Result<(), Failure> {
    let data = serde_json::to_vec(record)
        .map_err(|e| Failure::internal("broker_provisioning", format!("marshal: {e}")))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)
        .map_err(|e| Failure::internal("broker_provisioning", format!("mkdir: {e}")))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
        .map_err(|e| Failure::internal("broker_provisioning", format!("mkdir: {e}")))?;
    let tmp_path = path.with_extension("json.tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o400)
            .custom_flags(libc::O_CLOEXEC)
            .open(&tmp_path)
            .map_err(|e| Failure::internal("broker_provisioning", format!("write tmp: {e}")))?;
        use std::io::Write as _;
        file.write_all(&data)
            .and_then(|()| file.sync_all())
            .map_err(|e| {
                let _ = fs::remove_file(&tmp_path);
                Failure::internal("broker_provisioning", format!("sync tmp: {e}"))
            })?;
    }
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        Failure::internal("broker_provisioning", format!("rename: {e}"))
    })?;
    sync_dir(dir)
}

/// `validateTransition` — verbatim upstream:
/// - `next` state must be non-empty;
/// - same-state transitions move `recorded → candidate_staged →
///   baseline_installed → candidate_active`; `candidate_active` is
///   terminal within the same state; a no-op phase is admitted;
/// - `initializing → ready` requires `candidate_active`;
/// - any `→ absent` transition is admitted (deletion);
/// - anything else refuses.
pub fn validate_transition(
    current_state: &str,
    current_phase: &str,
    next_state: &str,
    next_phase: &str,
) -> Result<(), Failure> {
    if next_state.is_empty() {
        return Err(invalid("next state is empty"));
    }
    if current_state == next_state {
        if current_phase != next_phase {
            if current_phase == PHASE_RECORDED && next_phase != PHASE_CANDIDATE_STAGED {
                return Err(invalid(format!(
                    "invalid phase transition {current_phase} -> {next_phase} while state is {current_state}"
                )));
            }
            if current_phase == PHASE_CANDIDATE_STAGED && next_phase != PHASE_BASELINE_INSTALLED {
                return Err(invalid(format!(
                    "invalid phase transition {current_phase} -> {next_phase} while state is {current_state}"
                )));
            }
            if current_phase == PHASE_BASELINE_INSTALLED && next_phase != PHASE_CANDIDATE_ACTIVE {
                return Err(invalid(format!(
                    "invalid phase transition {current_phase} -> {next_phase} while state is {current_state}"
                )));
            }
            if current_phase == PHASE_CANDIDATE_ACTIVE {
                return Err(invalid(format!(
                    "cannot transition from terminal phase {current_phase} while state is {current_state}"
                )));
            }
        }
        return Ok(());
    }
    if current_state == PROV_RECORD_INITIALIZING && next_state == PROV_RECORD_READY {
        if current_phase != PHASE_CANDIDATE_ACTIVE {
            return Err(invalid(format!(
                "cannot transition to ready from phase {current_phase}, must be candidate_active first"
            )));
        }
        return Ok(());
    }
    if next_state == PROV_RECORD_ABSENT {
        return Ok(());
    }
    Err(invalid(format!(
        "invalid state transition {current_state}/{current_phase} -> {next_state}/{next_phase}"
    )))
}

// ---------------------------------------------------------------------------
// Tests — upstream `provisioning_store_test.go` coverage, ported.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::testutil::TempDir;
    use std::sync::Arc;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        }
    }

    fn record() -> ProvisioningRecord {
        ProvisioningRecord::absent_placeholder()
    }

    fn store(dir: &Path) -> ProvisioningStore {
        ProvisioningStore::new(
            dir.to_path_buf(),
            Some(Arc::new(Journal::new(
                dir.to_path_buf(),
                Arc::new(crate::broker::signing::SigningService::new()),
                None,
            ))),
        )
    }

    #[test]
    fn absent_read_is_not_found_sentinel() {
        let dir = TempDir::new("provisioning");
        let err = store(&dir).read_provisioning_record(&target()).unwrap_err();
        assert_eq!(
            err.kind(),
            central_foundation::failure::FailureKind::NotFound
        );
        assert!(err.message().contains(ERR_RECORD_ABSENT));
    }

    #[test]
    fn create_is_exclusive_and_normalized() {
        let dir = TempDir::new("provisioning");
        let store = store(&dir);
        let created = store
            .create_provisioning_record(&target(), record())
            .unwrap();
        assert_eq!(created.state, PROV_RECORD_INITIALIZING);
        assert_eq!(created.phase, PHASE_RECORDED);
        assert_eq!(created.revision, 1);
        assert_eq!(created.target.system_id, "sys-1");
        // O_EXCL — a second create is a denial, never a clobber.
        assert_eq!(
            store
                .create_provisioning_record(&target(), record())
                .unwrap_err()
                .kind(),
            central_foundation::failure::FailureKind::Denied
        );
        // The read returns the stored record.
        let read = store.read_provisioning_record(&target()).unwrap();
        assert_eq!(read.revision, 1);
    }

    #[test]
    fn replace_is_cas_with_transition_rules() {
        let dir = TempDir::new("provisioning");
        let store = store(&dir);
        let created = store
            .create_provisioning_record(&target(), record())
            .unwrap();
        // Wrong revision → denied.
        let mut next = created.clone();
        next.phase = PHASE_CANDIDATE_STAGED.into();
        let err = store
            .replace_provisioning_record(&ReplaceProvisioningRecordRequest {
                target: TargetIdentityWire::from(&target()),
                expected_revision: 99,
                next: next.clone(),
                journal_intent: ProvisioningJournalIntent {
                    operation_id: created.operation_id,
                    target_fingerprint: target_fingerprint(&target()),
                    previous_state: created.state.clone(),
                    previous_phase: created.phase.clone(),
                    next_state: next.state.clone(),
                    next_phase: next.phase.clone(),
                    reason: "test".into(),
                },
            })
            .unwrap_err();
        assert_eq!(err.kind(), central_foundation::failure::FailureKind::Denied);
        // Illegal transition — recorded → candidate_active skips.
        let mut bad = created.clone();
        bad.phase = PHASE_CANDIDATE_ACTIVE.into();
        let intent = ProvisioningJournalIntent {
            operation_id: created.operation_id,
            target_fingerprint: target_fingerprint(&target()),
            previous_state: created.state.clone(),
            previous_phase: created.phase.clone(),
            next_state: bad.state.clone(),
            next_phase: bad.phase.clone(),
            reason: "test".into(),
        };
        assert!(
            store
                .replace_provisioning_record(&ReplaceProvisioningRecordRequest {
                    target: TargetIdentityWire::from(&target()),
                    expected_revision: 1,
                    next: bad,
                    journal_intent: intent.clone(),
                })
                .is_err()
        );
        // Legal recorded → candidate_staged.
        let replaced = store
            .replace_provisioning_record(&ReplaceProvisioningRecordRequest {
                target: TargetIdentityWire::from(&target()),
                expected_revision: 1,
                next,
                journal_intent: intent,
            })
            .unwrap();
        assert_eq!(replaced.revision, 2);
        assert_eq!(replaced.phase, PHASE_CANDIDATE_STAGED);
        // initializing/recorded → ready requires candidate_active.
        let mut ready = replaced.clone();
        ready.state = PROV_RECORD_READY.into();
        assert!(
            store
                .replace_provisioning_record(&ReplaceProvisioningRecordRequest {
                    target: TargetIdentityWire::from(&target()),
                    expected_revision: 2,
                    next: ready,
                    journal_intent: ProvisioningJournalIntent {
                        operation_id: created.operation_id,
                        target_fingerprint: target_fingerprint(&target()),
                        previous_state: replaced.state.clone(),
                        previous_phase: replaced.phase.clone(),
                        next_state: PROV_RECORD_READY.into(),
                        next_phase: PHASE_CANDIDATE_STAGED.into(),
                        reason: "test".into(),
                    },
                })
                .is_err()
        );
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = TempDir::new("provisioning");
        let store = store(&dir);
        store
            .create_provisioning_record(&target(), record())
            .unwrap();
        store.delete_provisioning_record(&target()).unwrap();
        store.delete_provisioning_record(&target()).unwrap();
        assert_eq!(
            store
                .read_provisioning_record(&target())
                .unwrap_err()
                .kind(),
            central_foundation::failure::FailureKind::NotFound
        );
    }

    #[test]
    fn transition_table_matches_upstream() {
        // Same-state phase progression, terminal phase, ready gate,
        // absent escape hatch, and outright refusals.
        assert!(
            validate_transition(
                "initializing",
                "recorded",
                "initializing",
                "candidate_staged"
            )
            .is_ok()
        );
        assert!(
            validate_transition(
                "initializing",
                "candidate_staged",
                "initializing",
                "baseline_installed"
            )
            .is_ok()
        );
        assert!(
            validate_transition(
                "initializing",
                "baseline_installed",
                "initializing",
                "candidate_active"
            )
            .is_ok()
        );
        assert!(
            validate_transition("initializing", "candidate_active", "ready", "recorded").is_ok()
        );
        assert!(validate_transition("ready", "candidate_active", "absent", "recorded").is_ok());
        // no-op phase admitted
        assert!(
            validate_transition("initializing", "recorded", "initializing", "recorded").is_ok()
        );
        for (cs, cp, ns, np) in [
            ("initializing", "recorded", "ready", "recorded"),
            (
                "initializing",
                "candidate_active",
                "initializing",
                "recorded",
            ),
            (
                "initializing",
                "recorded",
                "initializing",
                "baseline_installed",
            ),
            ("initializing", "recorded", "bogus", "recorded"),
            ("ready", "recorded", "", "recorded"),
        ] {
            assert!(
                validate_transition(cs, cp, ns, np).is_err(),
                "admitted {cs}/{cp} -> {ns}/{np}"
            );
        }
    }
}
