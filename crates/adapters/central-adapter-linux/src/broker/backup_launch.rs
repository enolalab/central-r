//! `backup_launch.rs` — the port of upstream
//! `internal/adapter/authority/broker/backup_launch.go`: the
//! broker-side launch-evidence store for `backup-create` workers.
//!
//! The native supervisor mints an `issued` record binding the exact
//! worker it released (peer uid/gid/pid, executable, process start,
//! repository binding); the first live worker validation flips it to
//! `active`; `MarkReaped` is only permitted once the recorded PID no
//! longer resolves to the same process identity; `MarkCompleted`
//! pins the immutable attestation digests that
//! `CompleteAttestedBackupSeal` then compares against the broker-side
//! seal. Every record is HMAC-bound to the broker signing key over a
//! canonical payload and stored `0600` under a per-record lock.
//!
//! `helper.BackupLaunchEvidence`/`helper.BackupLaunchAuthority` from
//! upstream live here as [`BackupLaunchEvidence`]/
//! [`BackupLaunchAuthority`] — the evidence the supervisor presents
//! and the opaque authority it receives back.

use std::path::PathBuf;
use std::sync::Arc;

use central_backup::backup::operation::BackupOperation;
use central_backup::repository::{
    BackupRepositoryAttestation, BackupTargetLockAttestation, RepositoryBinding,
};
use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable;
use super::migration_launch::verify_peer_process;
use super::recovery_journal::{JOURNAL_UNAVAILABLE_CODE, RecoveryJournalStore, unavailable};
use super::signing::SigningService;
use super::wire;
use crate::sys::peercred::PeerCred;

const BACKUP_LAUNCH_DIRECTORY: &str = "backup-launches";
const BACKUP_LAUNCH_HMAC_DOMAIN: &str = "slice-c-backup-launch-v1";
const BACKUP_CREATE_MODE: &str = "backup-create";

/// `helper.BackupLaunchEvidence` — what the native supervisor proves
/// about the worker it is about to release.
#[derive(Debug, Clone)]
pub struct BackupLaunchEvidence {
    pub supervisor_launch_id: Uuid,
    pub pid: i32,
    pub process_start: String,
    pub executable: String,
    pub mode: String,
    pub operation_id: String,
    pub repository_binding: RepositoryBinding,
    pub expires_at: OffsetDateTime,
}

/// `helper.BackupLaunchAuthority` — the opaque operation/backup pair
/// fixed by the launch. It exposes neither repository locators nor
/// credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupLaunchAuthority {
    pub launch_evidence_id: Uuid,
    pub operation_id: Uuid,
    pub backup_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupLaunchState {
    Issued,
    Active,
    Reaped,
    Completed,
}

impl BackupLaunchState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Active => "active",
            Self::Reaped => "reaped",
            Self::Completed => "completed",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "issued" => Self::Issued,
            "active" => Self::Active,
            "reaped" => Self::Reaped,
            "completed" => Self::Completed,
            _ => return None,
        })
    }
}

/// `backup.RepositoryBinding` as Go's `json.Marshal` emits it inside
/// the record and its canonical payload: PascalCase fields, base64
/// `[32]byte` digests, RFC3339 timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBindingJournalWire {
    #[serde(rename = "BindingID")]
    pub(crate) binding_id: Uuid,
    #[serde(rename = "InstanceID")]
    instance_id: String,
    #[serde(rename = "OwnerUID")]
    owner_uid: u32,
    #[serde(rename = "OwnerGID")]
    owner_gid: u32,
    #[serde(rename = "DeviceMajor")]
    device_major: u64,
    #[serde(rename = "DeviceMinor")]
    device_minor: u64,
    #[serde(rename = "RootInode")]
    root_inode: u64,
    #[serde(rename = "MountID")]
    mount_id: u64,
    #[serde(rename = "CreatedAt", with = "wire::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(rename = "CreationNonce", with = "wire::b64")]
    creation_nonce: Vec<u8>,
    #[serde(rename = "ImmutableDigest", with = "wire::b64")]
    immutable_digest: Vec<u8>,
}

pub(crate) fn binding_to_wire(binding: &RepositoryBinding) -> RepositoryBindingJournalWire {
    RepositoryBindingJournalWire {
        binding_id: binding.binding_id,
        instance_id: binding.instance_id.clone(),
        owner_uid: binding.owner_uid,
        owner_gid: binding.owner_gid,
        device_major: binding.device_major,
        device_minor: binding.device_minor,
        root_inode: binding.root_inode,
        mount_id: binding.mount_id,
        created_at: binding.created_at,
        creation_nonce: binding.creation_nonce.to_vec(),
        immutable_digest: binding.immutable_digest.to_vec(),
    }
}

impl Default for RepositoryBindingJournalWire {
    fn default() -> Self {
        Self {
            binding_id: Uuid::nil(),
            instance_id: String::new(),
            owner_uid: 0,
            owner_gid: 0,
            device_major: 0,
            device_minor: 0,
            root_inode: 0,
            mount_id: 0,
            created_at: wire::go_zero_time(),
            creation_nonce: Vec::new(),
            immutable_digest: Vec::new(),
        }
    }
}

pub(crate) fn binding_from_wire(
    wire: &RepositoryBindingJournalWire,
) -> Result<RepositoryBinding, Failure> {
    let creation_nonce: [u8; 32] = wire
        .creation_nonce
        .clone()
        .try_into()
        .map_err(|_| unavailable())?;
    let immutable_digest: [u8; 32] = wire
        .immutable_digest
        .clone()
        .try_into()
        .map_err(|_| unavailable())?;
    Ok(RepositoryBinding {
        binding_id: wire.binding_id,
        instance_id: wire.instance_id.clone(),
        owner_uid: wire.owner_uid,
        owner_gid: wire.owner_gid,
        device_major: wire.device_major,
        device_minor: wire.device_minor,
        root_inode: wire.root_inode,
        mount_id: wire.mount_id,
        created_at: wire.created_at,
        creation_nonce,
        immutable_digest,
    })
}

/// `backupLaunchRecord` — the on-disk shape. `reaped_*`/`completed_*`
/// are `[32]byte` fields upstream: `,omitempty` never applies, so the
/// zero digest serializes as base64 zeros.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupLaunchRecordWire {
    supervisor_launch_id: Uuid,
    launch_evidence_id: Uuid,
    operation_id: Uuid,
    backup_id: Uuid,
    repository_binding: RepositoryBindingJournalWire,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    process_start: String,
    executable: String,
    mode: String,
    #[serde(with = "wire::rfc3339")]
    deadline: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    created_at: OffsetDateTime,
    state: String,
    #[serde(with = "wire::rfc3339")]
    reaped_at: OffsetDateTime,
    #[serde(with = "wire::b64")]
    reaped_target_lock_proof: Vec<u8>,
    #[serde(with = "wire::b64")]
    completed_attestation_hash: Vec<u8>,
    #[serde(with = "wire::b64")]
    completed_target_lock_hash: Vec<u8>,
    nonce: String,
    hmac_sha256: String,
}

/// `backupLaunchRecord` — domain-side shape; `None` ⇔ the Go zero
/// `time.Time`/`[32]byte`.
#[derive(Debug, Clone)]
struct BackupLaunchRecord {
    supervisor_launch_id: Uuid,
    launch_evidence_id: Uuid,
    operation_id: Uuid,
    backup_id: Uuid,
    repository_binding: RepositoryBinding,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    process_start: String,
    executable: String,
    mode: String,
    deadline: OffsetDateTime,
    created_at: OffsetDateTime,
    state: BackupLaunchState,
    reaped_at: Option<OffsetDateTime>,
    reaped_target_lock_proof: Option<[u8; 32]>,
    completed_attestation_hash: Option<[u8; 32]>,
    completed_target_lock_hash: Option<[u8; 32]>,
    nonce: String,
    hmac: String,
}

fn record_to_wire(record: &BackupLaunchRecord) -> Result<BackupLaunchRecordWire, Failure> {
    Ok(BackupLaunchRecordWire {
        supervisor_launch_id: record.supervisor_launch_id,
        launch_evidence_id: record.launch_evidence_id,
        operation_id: record.operation_id,
        backup_id: record.backup_id,
        repository_binding: binding_to_wire(&record.repository_binding),
        peer_uid: record.peer_uid,
        peer_gid: record.peer_gid,
        peer_pid: record.peer_pid,
        process_start: record.process_start.clone(),
        executable: record.executable.clone(),
        mode: record.mode.clone(),
        deadline: record.deadline.to_offset(time::UtcOffset::UTC),
        created_at: record.created_at.to_offset(time::UtcOffset::UTC),
        state: record.state.as_str().to_owned(),
        reaped_at: record.reaped_at.unwrap_or_else(wire::go_zero_time),
        reaped_target_lock_proof: record
            .reaped_target_lock_proof
            .map(|d| d.to_vec())
            .unwrap_or_else(|| vec![0u8; 32]),
        completed_attestation_hash: record
            .completed_attestation_hash
            .map(|d| d.to_vec())
            .unwrap_or_else(|| vec![0u8; 32]),
        completed_target_lock_hash: record
            .completed_target_lock_hash
            .map(|d| d.to_vec())
            .unwrap_or_else(|| vec![0u8; 32]),
        nonce: record.nonce.clone(),
        hmac_sha256: record.hmac.clone(),
    })
}

fn nonzero32(value: &[u8]) -> Result<Option<[u8; 32]>, Failure> {
    let digest: [u8; 32] = value.to_vec().try_into().map_err(|_| unavailable())?;
    if digest == [0u8; 32] {
        Ok(None)
    } else {
        Ok(Some(digest))
    }
}

fn record_from_wire(wire: &BackupLaunchRecordWire) -> Result<BackupLaunchRecord, Failure> {
    let Some(state) = BackupLaunchState::from_str(&wire.state) else {
        return Err(unavailable());
    };
    Ok(BackupLaunchRecord {
        supervisor_launch_id: wire.supervisor_launch_id,
        launch_evidence_id: wire.launch_evidence_id,
        operation_id: wire.operation_id,
        backup_id: wire.backup_id,
        repository_binding: binding_from_wire(&wire.repository_binding)?,
        peer_uid: wire.peer_uid,
        peer_gid: wire.peer_gid,
        peer_pid: wire.peer_pid,
        process_start: wire.process_start.clone(),
        executable: wire.executable.clone(),
        mode: wire.mode.clone(),
        deadline: wire.deadline,
        created_at: wire.created_at,
        state,
        reaped_at: if wire::is_go_zero_time(wire.reaped_at) {
            None
        } else {
            Some(wire.reaped_at)
        },
        reaped_target_lock_proof: nonzero32(&wire.reaped_target_lock_proof)?,
        completed_attestation_hash: nonzero32(&wire.completed_attestation_hash)?,
        completed_target_lock_hash: nonzero32(&wire.completed_target_lock_hash)?,
        nonce: wire.nonce.clone(),
        hmac: wire.hmac_sha256.clone(),
    })
}

/// `validBackupLaunchState` — field presence/absence by state.
fn valid_backup_launch_state(record: &BackupLaunchRecord) -> bool {
    match record.state {
        BackupLaunchState::Issued | BackupLaunchState::Active => {
            record.reaped_at.is_none()
                && record.reaped_target_lock_proof.is_none()
                && record.completed_attestation_hash.is_none()
                && record.completed_target_lock_hash.is_none()
        }
        BackupLaunchState::Reaped => {
            record.reaped_at.is_some()
                && record.reaped_target_lock_proof.is_some()
                && record.completed_attestation_hash.is_none()
                && record.completed_target_lock_hash.is_none()
        }
        BackupLaunchState::Completed => {
            record.reaped_at.is_some()
                && record.reaped_target_lock_proof.is_some()
                && record.completed_attestation_hash.is_some()
                && record.completed_target_lock_hash.is_some()
        }
    }
}

/// `backupLaunchRecordPayload` — the canonical HMAC input. UUIDs and
/// times are strings; the optional evidence fields are the hex
/// digests, omitted while empty.
#[derive(Serialize)]
struct BackupLaunchRecordPayload<'a> {
    supervisor_launch_id: String,
    launch_evidence_id: String,
    operation_id: String,
    backup_id: String,
    repository_binding: &'a RepositoryBindingJournalWire,
    peer_uid: u32,
    peer_gid: u32,
    peer_pid: i32,
    process_start: &'a str,
    executable: &'a str,
    mode: &'a str,
    deadline: String,
    created_at: String,
    state: &'a str,
    #[serde(skip_serializing_if = "String::is_empty")]
    reaped_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    reaped_target_lock_proof_sha256: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    completed_attestation_hash_sha256: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    completed_target_lock_hash_sha256: String,
    nonce: &'a str,
}

fn canonical_payload(record: &BackupLaunchRecord) -> Result<Vec<u8>, Failure> {
    let Some(nonce_bytes) = wire::hex_decode(&record.nonce) else {
        return Err(unavailable());
    };
    if record.supervisor_launch_id.is_nil()
        || record.launch_evidence_id.is_nil()
        || record.operation_id.is_nil()
        || record.backup_id.is_nil()
        || record.repository_binding.verify().is_err()
        || record.peer_pid <= 0
        || record.process_start.is_empty()
        || record.executable.is_empty()
        || record.mode != BACKUP_CREATE_MODE
        || wire::is_go_zero_time(record.deadline)
        || wire::is_go_zero_time(record.created_at)
        || nonce_bytes.len() != 32
        || !valid_backup_launch_state(record)
    {
        return Err(unavailable());
    }
    let binding_wire = binding_to_wire(&record.repository_binding);
    let payload = BackupLaunchRecordPayload {
        supervisor_launch_id: record.supervisor_launch_id.to_string(),
        launch_evidence_id: record.launch_evidence_id.to_string(),
        operation_id: record.operation_id.to_string(),
        backup_id: record.backup_id.to_string(),
        repository_binding: &binding_wire,
        peer_uid: record.peer_uid,
        peer_gid: record.peer_gid,
        peer_pid: record.peer_pid,
        process_start: &record.process_start,
        executable: &record.executable,
        mode: &record.mode,
        deadline: wire::format_rfc3339_nano(record.deadline.to_offset(time::UtcOffset::UTC)),
        created_at: wire::format_rfc3339_nano(record.created_at.to_offset(time::UtcOffset::UTC)),
        state: record.state.as_str(),
        reaped_at: record
            .reaped_at
            .map(|at| wire::format_rfc3339_nano(at.to_offset(time::UtcOffset::UTC)))
            .unwrap_or_default(),
        reaped_target_lock_proof_sha256: record
            .reaped_target_lock_proof
            .map(|d| wire::hex_encode(&d))
            .unwrap_or_default(),
        completed_attestation_hash_sha256: record
            .completed_attestation_hash
            .map(|d| wire::hex_encode(&d))
            .unwrap_or_default(),
        completed_target_lock_hash_sha256: record
            .completed_target_lock_hash
            .map(|d| wire::hex_encode(&d))
            .unwrap_or_default(),
        nonce: &record.nonce,
    };
    serde_json::to_vec(&payload).map_err(|_| unavailable())
}

/// `BackupLaunchStore` — the broker-side launch-evidence store for
/// `backup-create` workers.
pub struct BackupLaunchStore {
    root: PathBuf,
    signing: Arc<SigningService>,
    journal: Arc<RecoveryJournalStore>,
    runtime_uid: u32,
    runtime_gid: u32,
}

impl BackupLaunchStore {
    /// `newBackupLaunchStore`.
    pub fn new(
        broker_root: &std::path::Path,
        signing: Arc<SigningService>,
        journal: Arc<RecoveryJournalStore>,
        runtime_uid: u32,
        runtime_gid: u32,
    ) -> Result<Self, Failure> {
        let root = broker_root.join(BACKUP_LAUNCH_DIRECTORY);
        durable::mkdir_p(&root, durable::PRIVATE_DIRECTORY_MODE).map_err(|e| {
            Failure::internal(
                JOURNAL_UNAVAILABLE_CODE,
                format!("backup launch store: create root: {e}"),
            )
        })?;
        durable::validate_private_directory(&root, "backup launch root")?;
        Ok(Self {
            root,
            signing,
            journal,
            runtime_uid,
            runtime_gid,
        })
    }

    /// `Issue` — binds the exact live worker the native supervisor is
    /// about to release.
    pub fn issue(&self, evidence: &BackupLaunchEvidence) -> Result<BackupLaunchAuthority, Failure> {
        if evidence.supervisor_launch_id.is_nil()
            || evidence.mode != BACKUP_CREATE_MODE
            || evidence.pid <= 0
            || evidence.process_start.is_empty()
            || evidence.executable.is_empty()
            || evidence.repository_binding.verify().is_err()
            || evidence.repository_binding.owner_uid != self.runtime_uid
            || evidence.repository_binding.owner_gid != self.runtime_gid
            || wire::is_go_zero_time(evidence.expires_at)
            || OffsetDateTime::now_utc() >= evidence.expires_at
        {
            return Err(unavailable());
        }
        let Ok(operation_id) = Uuid::parse_str(&evidence.operation_id) else {
            return Err(unavailable());
        };
        let backup_id = Uuid::now_v7();
        let Ok((executable, process_start)) = verify_peer_process(evidence.pid) else {
            return Err(unavailable());
        };
        if executable != evidence.executable || process_start != evidence.process_start {
            return Err(unavailable());
        }
        let launch_id = Uuid::now_v7();
        let mut nonce = [0u8; 32];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| unavailable())?;
        let mut record = BackupLaunchRecord {
            supervisor_launch_id: evidence.supervisor_launch_id,
            launch_evidence_id: launch_id,
            operation_id,
            backup_id,
            repository_binding: evidence.repository_binding.clone(),
            peer_uid: self.runtime_uid,
            peer_gid: self.runtime_gid,
            peer_pid: evidence.pid,
            process_start: evidence.process_start.clone(),
            executable: evidence.executable.clone(),
            mode: evidence.mode.clone(),
            deadline: evidence.expires_at.to_offset(time::UtcOffset::UTC),
            created_at: OffsetDateTime::now_utc(),
            state: BackupLaunchState::Issued,
            reaped_at: None,
            reaped_target_lock_proof: None,
            completed_attestation_hash: None,
            completed_target_lock_hash: None,
            nonce: wire::hex_encode(&nonce),
            hmac: String::new(),
        };
        if self.sign_record(&mut record).is_err()
            || self
                .journal
                .write_exclusive_json(&self.path(launch_id), &record_to_wire(&record)?)
                .is_err()
        {
            return Err(unavailable());
        }
        Ok(BackupLaunchAuthority {
            launch_evidence_id: launch_id,
            operation_id,
            backup_id,
        })
    }

    /// `WorkerAuthority` — validates the exact live worker identity
    /// and returns only the opaque operation/backup pair already
    /// fixed by the root-helper launch.
    pub fn worker_authority(
        &self,
        launch_evidence_id: Uuid,
        peer: &PeerCred,
    ) -> Result<BackupLaunchAuthority, Failure> {
        self.validate_worker(launch_evidence_id, Uuid::nil(), peer)?;
        let record = self.read(launch_evidence_id)?;
        Ok(BackupLaunchAuthority {
            launch_evidence_id: record.launch_evidence_id,
            operation_id: record.operation_id,
            backup_id: record.backup_id,
        })
    }

    /// `ValidateWorker` — uid/gid match, live process identity, valid
    /// deadline; `issued` → `active` on success.
    pub fn validate_worker(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if launch_evidence_id.is_nil()
            || peer.uid.as_raw() != self.runtime_uid
            || peer.gid.as_raw() != self.runtime_gid
            || peer.pid.as_raw_pid() <= 0
        {
            return Err(unavailable());
        }
        let lock = self
            .journal
            .open_lock(&self.path(launch_evidence_id))
            .map_err(|_| unavailable())?;
        let result = (|| -> Result<(), Failure> {
            let mut record = self.read(launch_evidence_id)?;
            if (!operation_id.is_nil() && record.operation_id != operation_id)
                || record.peer_uid != peer.uid.as_raw()
                || record.peer_gid != peer.gid.as_raw()
                || record.peer_pid != peer.pid.as_raw_pid()
                || !matches!(
                    record.state,
                    BackupLaunchState::Issued | BackupLaunchState::Active
                )
                || OffsetDateTime::now_utc() >= record.deadline
            {
                return Err(unavailable());
            }
            let Ok((executable, process_start)) = verify_peer_process(peer.pid.as_raw_pid()) else {
                return Err(unavailable());
            };
            if executable != record.executable || process_start != record.process_start {
                return Err(unavailable());
            }
            if record.state == BackupLaunchState::Issued {
                record.state = BackupLaunchState::Active;
                if self.sign_record(&mut record).is_err()
                    || self
                        .journal
                        .replace_json(&self.path(launch_evidence_id), &record_to_wire(&record)?)
                        .is_err()
                {
                    return Err(unavailable());
                }
            }
            Ok(())
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `ValidateWorkerOperation` — closes every journal mutation over
    /// the exact IDs allocated before the native supervisor released
    /// the worker. Once accepted, the repository binding must also
    /// match the helper-retained descriptor.
    pub fn validate_worker_operation(
        &self,
        launch_evidence_id: Uuid,
        operation: &BackupOperation,
        peer: &PeerCred,
    ) -> Result<(), Failure> {
        if operation.validate().is_err()
            || self
                .validate_worker(launch_evidence_id, operation.operation_id, peer)
                .is_err()
        {
            return Err(unavailable());
        }
        let record = self.read(launch_evidence_id)?;
        if record.backup_id != operation.backup_id {
            return Err(unavailable());
        }
        if operation.phase != central_backup::backup::operation::BackupPhase::Planned
            && operation.accepted_facts.repository_binding_id
                != record.repository_binding.binding_id
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// `MarkReaped` — only once the recorded PID no longer resolves
    /// to the same process identity.
    pub fn mark_reaped(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        target_lock_proof: [u8; 32],
        at: OffsetDateTime,
    ) -> Result<(), Failure> {
        if launch_evidence_id.is_nil()
            || operation_id.is_nil()
            || target_lock_proof == [0u8; 32]
            || wire::is_go_zero_time(at)
        {
            return Err(unavailable());
        }
        let lock = self
            .journal
            .open_lock(&self.path(launch_evidence_id))
            .map_err(|_| unavailable())?;
        let result = (|| -> Result<(), Failure> {
            let mut record = self.read(launch_evidence_id)?;
            if record.operation_id != operation_id
                || !matches!(
                    record.state,
                    BackupLaunchState::Active
                        | BackupLaunchState::Reaped
                        | BackupLaunchState::Completed
                )
            {
                return Err(unavailable());
            }
            if matches!(
                record.state,
                BackupLaunchState::Reaped | BackupLaunchState::Completed
            ) {
                if record.reaped_target_lock_proof != Some(target_lock_proof) {
                    return Err(unavailable());
                }
                return Ok(());
            }
            if let Ok((executable, process_start)) = verify_peer_process(record.peer_pid)
                && executable == record.executable
                && process_start == record.process_start
            {
                return Err(unavailable());
            }
            record.state = BackupLaunchState::Reaped;
            record.reaped_at = Some(at.to_offset(time::UtcOffset::UTC));
            record.reaped_target_lock_proof = Some(target_lock_proof);
            if self.sign_record(&mut record).is_err()
                || self
                    .journal
                    .replace_json(&self.path(launch_evidence_id), &record_to_wire(&record)?)
                    .is_err()
            {
                return Err(unavailable());
            }
            Ok(())
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `RequireReaped` — the helper-facing gate the attested seal
    /// completion re-checks.
    pub fn require_reaped(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        repository: &BackupRepositoryAttestation,
        target_lock: &BackupTargetLockAttestation,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let record = self.read(launch_evidence_id)?;
        let reaped_hex = record
            .reaped_target_lock_proof
            .map(|d| wire::hex_encode(&d))
            .unwrap_or_default();
        if wire::is_go_zero_time(now)
            || record.operation_id != operation_id
            || record.backup_id != repository.backup_id
            || record.repository_binding.binding_id != repository.repository_binding_id
            || record.supervisor_launch_id != target_lock.supervisor_launch_id
            || repository.launch_evidence_id != launch_evidence_id
            || repository.operation_id != operation_id
            || repository.verify().is_err()
            || target_lock.launch_evidence_id != launch_evidence_id
            || target_lock.operation_id != operation_id
            || target_lock.backup_id != record.backup_id
            || target_lock.target_lock_proof != format!("sha256:{reaped_hex}")
            || repository.attested_at < record.reaped_at.unwrap_or_else(wire::go_zero_time)
            || target_lock.asserted_at < record.reaped_at.unwrap_or_else(wire::go_zero_time)
        {
            return Err(unavailable());
        }
        if record.state == BackupLaunchState::Completed {
            if record.completed_attestation_hash != Some(repository.immutable_digest)
                || record.completed_target_lock_hash != Some(target_lock.immutable_digest)
            {
                return Err(unavailable());
            }
            return Ok(());
        }
        if record.state != BackupLaunchState::Reaped || target_lock.valid_at(now).is_err() {
            return Err(unavailable());
        }
        Ok(())
    }

    /// `MarkCompleted` — pins the immutable attestation digests into
    /// the launch record for `CompleteAttestedBackupSeal` to compare.
    pub fn mark_completed(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        repository: &BackupRepositoryAttestation,
        target_lock: &BackupTargetLockAttestation,
    ) -> Result<(), Failure> {
        let lock = self
            .journal
            .open_lock(&self.path(launch_evidence_id))
            .map_err(|_| unavailable())?;
        let result = (|| -> Result<(), Failure> {
            let mut record = self.read(launch_evidence_id)?;
            let reaped_hex = record
                .reaped_target_lock_proof
                .map(|d| wire::hex_encode(&d))
                .unwrap_or_default();
            if record.operation_id != operation_id
                || record.backup_id != repository.backup_id
                || record.repository_binding.binding_id != repository.repository_binding_id
                || record.supervisor_launch_id != target_lock.supervisor_launch_id
                || target_lock.target_lock_proof != format!("sha256:{reaped_hex}")
            {
                return Err(unavailable());
            }
            if record.state == BackupLaunchState::Completed {
                if record.completed_attestation_hash != Some(repository.immutable_digest)
                    || record.completed_target_lock_hash != Some(target_lock.immutable_digest)
                {
                    return Err(unavailable());
                }
                return Ok(());
            }
            if record.state != BackupLaunchState::Reaped
                || repository.attested_at < record.reaped_at.unwrap_or_else(wire::go_zero_time)
                || target_lock.asserted_at < record.reaped_at.unwrap_or_else(wire::go_zero_time)
            {
                return Err(unavailable());
            }
            record.state = BackupLaunchState::Completed;
            record.completed_attestation_hash = Some(repository.immutable_digest);
            record.completed_target_lock_hash = Some(target_lock.immutable_digest);
            if self.sign_record(&mut record).is_err()
                || self
                    .journal
                    .replace_json(&self.path(launch_evidence_id), &record_to_wire(&record)?)
                    .is_err()
            {
                return Err(unavailable());
            }
            Ok(())
        })();
        durable::unlock_and_close(lock);
        result
    }

    /// `s.read` — strict decode, full structural validation, then the
    /// broker-HMAC over the canonical payload.
    fn read(&self, id: Uuid) -> Result<BackupLaunchRecord, Failure> {
        let wire_record: BackupLaunchRecordWire =
            super::recovery_journal::read_private_json(&self.path(id))?;
        let record = record_from_wire(&wire_record)?;
        if id.is_nil()
            || record.supervisor_launch_id.is_nil()
            || record.launch_evidence_id != id
            || record.operation_id.is_nil()
            || record.backup_id.is_nil()
            || record.repository_binding.verify().is_err()
            || record.repository_binding.owner_uid != self.runtime_uid
            || record.repository_binding.owner_gid != self.runtime_gid
            || record.peer_uid != self.runtime_uid
            || record.peer_gid != self.runtime_gid
            || record.peer_pid <= 0
            || record.process_start.is_empty()
            || record.executable.is_empty()
            || record.mode != BACKUP_CREATE_MODE
            || wire::is_go_zero_time(record.deadline)
            || wire::is_go_zero_time(record.created_at)
            || record.created_at > record.deadline
            || !valid_backup_launch_state(&record)
        {
            return Err(unavailable());
        }
        let payload = canonical_payload(&record)?;
        let want = self
            .signing
            .fingerprint(BACKUP_LAUNCH_HMAC_DOMAIN, &payload);
        if !wire::hmac_equal(record.hmac.as_bytes(), want.as_bytes()) {
            return Err(unavailable());
        }
        Ok(record)
    }

    /// `s.signRecord` — HMAC over the canonical payload.
    fn sign_record(&self, record: &mut BackupLaunchRecord) -> Result<(), Failure> {
        let payload = canonical_payload(record)?;
        record.hmac = self
            .signing
            .fingerprint(BACKUP_LAUNCH_HMAC_DOMAIN, &payload);
        Ok(())
    }

    /// `s.path` — upstream uses the launch ID verbatim
    /// (`id.String()+".json"`), not the generation key.
    fn path(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Child, Command};
    use std::sync::Arc;

    use central_backup::repository::{
        BackupSealPublication, RepositoryBinding, new_backup_repository_attestation,
        new_backup_target_lock_attestation, new_repository_binding,
    };
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::*;
    use crate::broker::protected_file::ProtectedFileBackend;
    use crate::broker::testutil::TempDir;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    struct Env {
        _dir: TempDir,
        store: BackupLaunchStore,
        uid: u32,
        gid: u32,
    }

    fn env() -> Env {
        let dir = TempDir::new("backup-launch");
        let backend = ProtectedFileBackend::new(dir.join("protected"));
        let signing = Arc::new(SigningService::new());
        let journal = Arc::new(RecoveryJournalStore::new(&dir, signing.clone(), backend).unwrap());
        let uid = rustix::process::geteuid().as_raw();
        let gid = rustix::process::getegid().as_raw();
        let store = BackupLaunchStore::new(&dir, signing, journal, uid, gid).unwrap();
        Env {
            _dir: dir,
            store,
            uid,
            gid,
        }
    }

    /// A live child whose `/proc` identity satisfies `Issue`.
    fn spawn_worker() -> (Child, i32, String, String) {
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let (executable, process_start) = verify_peer_process(pid).unwrap();
        (child, pid, executable, process_start)
    }

    fn cred(pid: i32, uid: u32, gid: u32) -> PeerCred {
        PeerCred {
            pid: rustix::process::Pid::from_raw(pid).unwrap(),
            uid: rustix::process::Uid::from_raw(uid),
            gid: rustix::process::Gid::from_raw(gid),
        }
    }

    fn binding(uid: u32, gid: u32) -> RepositoryBinding {
        new_repository_binding(
            Uuid::now_v7(),
            "repo-1",
            uid,
            gid,
            8,
            0,
            42,
            7,
            now(),
            [0x55u8; 32],
        )
        .unwrap()
    }

    fn evidence(
        pid: i32,
        executable: &str,
        process_start: &str,
        binding: RepositoryBinding,
    ) -> BackupLaunchEvidence {
        BackupLaunchEvidence {
            supervisor_launch_id: Uuid::now_v7(),
            pid,
            process_start: process_start.to_owned(),
            executable: executable.to_owned(),
            mode: BACKUP_CREATE_MODE.to_owned(),
            operation_id: Uuid::now_v7().to_string(),
            repository_binding: binding,
            expires_at: now() + Duration::seconds(60),
        }
    }

    #[test]
    fn issue_validate_reaped_completed_lifecycle() {
        let env = env();
        let (mut child, pid, exe, start) = spawn_worker();
        let bind = binding(env.uid, env.gid);
        let binding_id = bind.binding_id;
        let ev = evidence(pid, &exe, &start, bind);
        let authority = env.store.issue(&ev).unwrap();
        let peer = cred(pid, env.uid, env.gid);

        // Foreign uid is refused.
        let foreign = cred(pid, env.uid.wrapping_add(1), env.gid);
        assert!(
            env.store
                .validate_worker(authority.launch_evidence_id, Uuid::nil(), &foreign)
                .is_err()
        );
        // Wrong live pid is refused.
        let wrong_pid = cred(std::process::id() as i32, env.uid, env.gid);
        assert!(
            env.store
                .validate_worker(authority.launch_evidence_id, Uuid::nil(), &wrong_pid)
                .is_err()
        );

        // The bound worker validates and moves issued → active.
        env.store
            .validate_worker(authority.launch_evidence_id, Uuid::nil(), &peer)
            .unwrap();
        let again = env
            .store
            .worker_authority(authority.launch_evidence_id, &peer)
            .unwrap();
        assert_eq!(again, authority);

        // Reaping while the worker still lives is refused.
        let proof = [0xabu8; 32];
        assert!(
            env.store
                .mark_reaped(
                    authority.launch_evidence_id,
                    authority.operation_id,
                    proof,
                    now(),
                )
                .is_err()
        );
        child.kill().unwrap();
        child.wait().unwrap();
        env.store
            .mark_reaped(
                authority.launch_evidence_id,
                authority.operation_id,
                proof,
                now(),
            )
            .unwrap();

        // Attested completion binds launch + attestation + lock.
        let publication = BackupSealPublication {
            operation_id: authority.operation_id,
            backup_id: authority.backup_id,
            repository_binding_id: binding_id,
            root_manifest_digest: [1u8; 32],
            seal_companion_digest: [2u8; 32],
            file_tree_digest: [3u8; 32],
            repository_manifest_digest: [4u8; 32],
            repository_revision: 1,
        };
        let attestation =
            new_backup_repository_attestation(authority.launch_evidence_id, &publication, now())
                .unwrap();
        let target_lock = new_backup_target_lock_attestation(
            ev.supervisor_launch_id,
            authority.launch_evidence_id,
            authority.operation_id,
            authority.backup_id,
            proof,
            now(),
        )
        .unwrap();
        env.store
            .require_reaped(
                authority.launch_evidence_id,
                authority.operation_id,
                &attestation,
                &target_lock,
                now(),
            )
            .unwrap();
        env.store
            .mark_completed(
                authority.launch_evidence_id,
                authority.operation_id,
                &attestation,
                &target_lock,
            )
            .unwrap();
        // Both replay idempotently once completed.
        env.store
            .mark_completed(
                authority.launch_evidence_id,
                authority.operation_id,
                &attestation,
                &target_lock,
            )
            .unwrap();
        env.store
            .require_reaped(
                authority.launch_evidence_id,
                authority.operation_id,
                &attestation,
                &target_lock,
                now(),
            )
            .unwrap();
        // A different proof can never re-reap the record.
        assert!(
            env.store
                .mark_reaped(
                    authority.launch_evidence_id,
                    authority.operation_id,
                    [0xcdu8; 32],
                    now(),
                )
                .is_err()
        );
    }

    #[test]
    fn issue_refuses_deadline_mode_and_foreign_identity() {
        let env = env();
        let (_child, pid, exe, start) = spawn_worker();
        let bind = binding(env.uid, env.gid);
        let mut ev = evidence(pid, &exe, &start, bind.clone());
        // Already-expired deadline.
        ev.expires_at = now() - Duration::seconds(1);
        assert!(env.store.issue(&ev).is_err());
        // Wrong mode.
        ev = evidence(pid, &exe, &start, bind.clone());
        ev.mode = "backup-verify".to_owned();
        assert!(env.store.issue(&ev).is_err());
        // Executable does not match the live /proc identity.
        ev = evidence(pid, "/bin/sh", &start, bind.clone());
        assert!(env.store.issue(&ev).is_err());
        // Fabricated process start does not match either.
        ev = evidence(pid, &exe, "not-a-start-time", bind);
        assert!(env.store.issue(&ev).is_err());
        // A binding owned by another uid is refused.
        let foreign_binding = binding(env.uid.wrapping_add(1), env.gid);
        let ev = evidence(pid, &exe, &start, foreign_binding);
        assert!(env.store.issue(&ev).is_err());
    }

    #[test]
    fn validate_worker_operation_pins_operation_and_backup() {
        use central_backup::backup::operation::new_backup_operation;
        use central_backup::domain::TargetIdentity;
        let env = env();
        let (mut child, pid, exe, start) = spawn_worker();
        let bind = binding(env.uid, env.gid);
        let ev = evidence(pid, &exe, &start, bind);
        let authority = env.store.issue(&ev).unwrap();
        let target = TargetIdentity {
            system_id: "sys-1".to_owned(),
            database_oid: "16400".to_owned(),
            database: "central".to_owned(),
            config_hash: format!("sha256:{}", "a".repeat(64)),
            epoch: 7,
        };
        let planned =
            new_backup_operation(authority.operation_id, authority.backup_id, target, now())
                .unwrap();
        // The wrong operation id is refused even for a valid peer.
        let peer = cred(pid, env.uid, env.gid);
        let mut other = planned.clone();
        other.operation_id = Uuid::now_v7();
        assert!(
            env.store
                .validate_worker_operation(authority.launch_evidence_id, &other, &peer)
                .is_err()
        );
        // The pinned operation validates.
        env.store
            .validate_worker_operation(authority.launch_evidence_id, &planned, &peer)
            .unwrap();
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
