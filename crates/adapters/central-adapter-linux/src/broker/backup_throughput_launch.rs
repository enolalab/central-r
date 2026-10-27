//! `backupThroughputLaunchStore` — launch-evidence store for the
//! `throughput-probe` worker. Port of upstream
//! `backup_throughput_launch.go`; same locking/HMAC/durability
//! discipline as `backup_launch.rs`, plus the
//! issued→active→target_locked→fixture_loaded→measurement_staged
//! progress chain bound to the throughput journal's acceptance
//! window.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use central_backup::backup::capacity::MAXIMUM_THROUGHPUT_PROBE_ELAPSED;
use central_backup::recovery::profile::{ThroughputEvidence, ThroughputEvidenceBinding};
use central_foundation::failure::Failure;
use central_infra::domain::{MINIO_BACKUP_KEY_SCOPE, Purpose};

const CENTRAL_ARTIFACTS_BUCKET: &str = "central-artifacts-v1";
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::backup_launch::{RepositoryBindingJournalWire, binding_from_wire};
use super::durable;
use super::migration_launch::verify_peer_process;
use super::payload_epoch::PayloadEpochStore;
use super::recovery_journal::{RecoveryJournalStore, read_private_json};
use super::signing::SigningService;
use super::throughput_journal::{ThroughputJournalStore, throughput_evidence_digest};
use super::wire;
use crate::sys::peercred::PeerCred;

const BACKUP_THROUGHPUT_LAUNCH_DIRECTORY: &str = "backup-throughput-launches";
const BACKUP_THROUGHPUT_LAUNCH_SCHEMA: &str = "central.backup-throughput-launch/v1";
const BACKUP_THROUGHPUT_LAUNCH_HMAC_DOMAIN: &str = "slice-c-backup-throughput-launch-v1";
const BACKUP_THROUGHPUT_WORKER_EXECUTABLE: &str = "/usr/lib/central/central-backup";
const BACKUP_THROUGHPUT_WORKER_MODE: &str = "throughput-probe";

pub const BACKUP_THROUGHPUT_LAUNCH_ISSUED: &str = "issued";
pub const BACKUP_THROUGHPUT_LAUNCH_ACTIVE: &str = "active";
pub const BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED: &str = "target_locked";
pub const BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED: &str = "fixture_loaded";
pub const BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED: &str = "measurement_staged";

fn unavailable() -> Failure {
    Failure::internal(
        super::recovery_journal::JOURNAL_UNAVAILABLE_CODE,
        "broker: throughput journal unavailable",
    )
}

fn is_v7(id: Uuid) -> bool {
    id.get_version_num() == 7
}

/// `BackupThroughputStaticBinding` — the environment-static part of
/// the throughput binding (snake_case RPC shape; the target
/// fingerprint arrives only at target-lock time).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupThroughputStaticBinding {
    pub instance_id: Uuid,
    pub payload_epoch_id: Uuid,
    pub repository_binding_id: Uuid,
    pub device_mount_set_digest: String,
    pub host_profile_digest: String,
    pub dependency_provisioning_digest: String,
    pub postgres_image_digest: String,
    pub minio_image_digest: String,
    pub pg_dump_tool_digest: String,
    pub pg_dump_tool_version: String,
    pub config_digest: String,
    pub minio_backup_policy_digest: String,
    pub fixture_digest: String,
    pub transfer_envelope_version: String,
    pub transfer_envelope_digest: String,
}

impl BackupThroughputStaticBinding {
    /// `Validate`.
    pub fn validate(&self) -> Result<(), Failure> {
        self.with_target_fingerprint(&format!("sha256:{}", "0".repeat(64)))
            .map(|_| ())
    }

    /// `WithTargetFingerprint`.
    pub fn with_target_fingerprint(
        &self,
        target_fingerprint: &str,
    ) -> Result<ThroughputEvidenceBinding, Failure> {
        let full = ThroughputEvidenceBinding {
            instance_id: self.instance_id,
            payload_epoch_id: self.payload_epoch_id,
            target_fingerprint: target_fingerprint.to_string(),
            repository_binding_id: self.repository_binding_id,
            device_mount_set_digest: self.device_mount_set_digest.clone(),
            host_profile_digest: self.host_profile_digest.clone(),
            dependency_provisioning_digest: self.dependency_provisioning_digest.clone(),
            postgres_image_digest: self.postgres_image_digest.clone(),
            minio_image_digest: self.minio_image_digest.clone(),
            pg_dump_tool_digest: self.pg_dump_tool_digest.clone(),
            pg_dump_tool_version: self.pg_dump_tool_version.clone(),
            config_digest: self.config_digest.clone(),
            minio_backup_policy_digest: self.minio_backup_policy_digest.clone(),
            fixture_digest: self.fixture_digest.clone(),
            transfer_envelope_version: self.transfer_envelope_version.clone(),
            transfer_envelope_digest: self.transfer_envelope_digest.clone(),
        };
        if full.validate().is_err() {
            return Err(unavailable());
        }
        Ok(full)
    }
}

/// `staticBackupThroughputBinding`.
pub fn static_backup_throughput_binding(
    full: &ThroughputEvidenceBinding,
) -> BackupThroughputStaticBinding {
    BackupThroughputStaticBinding {
        instance_id: full.instance_id,
        payload_epoch_id: full.payload_epoch_id,
        repository_binding_id: full.repository_binding_id,
        device_mount_set_digest: full.device_mount_set_digest.clone(),
        host_profile_digest: full.host_profile_digest.clone(),
        dependency_provisioning_digest: full.dependency_provisioning_digest.clone(),
        postgres_image_digest: full.postgres_image_digest.clone(),
        minio_image_digest: full.minio_image_digest.clone(),
        pg_dump_tool_digest: full.pg_dump_tool_digest.clone(),
        pg_dump_tool_version: full.pg_dump_tool_version.clone(),
        config_digest: full.config_digest.clone(),
        minio_backup_policy_digest: full.minio_backup_policy_digest.clone(),
        fixture_digest: full.fixture_digest.clone(),
        transfer_envelope_version: full.transfer_envelope_version.clone(),
        transfer_envelope_digest: full.transfer_envelope_digest.clone(),
    }
}

/// `BackupThroughputLaunchEvidence`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupThroughputLaunchEvidence {
    pub supervisor_launch_id: Uuid,
    pub operation_id: Uuid,
    pub pid: i32,
    pub process_start: String,
    pub executable: String,
    pub mode: String,
    pub repository_binding: RepositoryBindingJournalWire,
    pub static_binding: BackupThroughputStaticBinding,
    #[serde(with = "wire::rfc3339")]
    pub deadline: OffsetDateTime,
}

/// `BackupThroughputLaunchAuthority`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupThroughputLaunchAuthority {
    pub launch_evidence_id: Uuid,
    pub operation_id: Uuid,
    #[serde(with = "wire::rfc3339")]
    pub deadline: OffsetDateTime,
}

/// `BackupThroughputWorkerContext`. `Deserialize` is the worker-side
/// read half (`BackupThroughputWorkerAuthority.WorkerContext`) —
/// `default` covers every field the omitempty rules may drop, exactly
/// like Go's zero-value decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupThroughputWorkerContext {
    pub launch_evidence_id: Uuid,
    pub operation_id: Uuid,
    pub phase: String,
    #[serde(with = "wire::rfc3339")]
    pub accepted_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub deadline: OffsetDateTime,
    pub static_binding: BackupThroughputStaticBinding,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_fingerprint: String,
    /// `time.Duration` `,omitempty` — nanoseconds; omitted when zero.
    #[serde(
        rename = "fixture_load_elapsed",
        default,
        skip_serializing_if = "duration_is_zero",
        serialize_with = "ser_duration_ns",
        deserialize_with = "de_duration_ns"
    )]
    pub fixture_load_elapsed: time::Duration,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provision_receipt_binding: String,
}

fn duration_is_zero(d: &time::Duration) -> bool {
    d.is_zero()
}

fn ser_duration_ns<S: serde::Serializer>(d: &time::Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_i64(d.whole_nanoseconds() as i64)
}

/// `BackupThroughputTargetLockAttestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupThroughputTargetLockAttestation {
    pub target_fingerprint: String,
    pub target_lock_proof_sha256: [u8; 32],
    #[serde(with = "wire::rfc3339")]
    pub locked_at: OffsetDateTime,
}

/// `BackupThroughputFixtureLoadAttestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupThroughputFixtureLoadAttestation {
    #[serde(
        rename = "fixture_load_elapsed",
        deserialize_with = "de_duration_ns",
        serialize_with = "ser_duration_ns"
    )]
    pub fixture_load_elapsed: time::Duration,
    pub provision_receipt_binding: String,
    pub minio_seed_binding: String,
    #[serde(with = "wire::rfc3339")]
    pub loaded_at: OffsetDateTime,
}

fn de_duration_ns<'de, D: serde::Deserializer<'de>>(d: D) -> Result<time::Duration, D::Error> {
    let ns = i64::deserialize(d)?;
    Ok(time::Duration::nanoseconds(ns))
}

/// `BackupThroughputLaunchStatus`. `Deserialize` is the
/// root-helper's read half (`BackupThroughputLaunchIssuer.ReadState`)
/// — `default` covers every field the omitempty rules may drop,
/// exactly like Go's zero-value decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupThroughputLaunchStatus {
    pub supervisor_launch_id: Uuid,
    pub launch_evidence_id: Uuid,
    pub operation_id: Uuid,
    pub repository_binding_id: Uuid,
    pub phase: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_fingerprint: String,
    /// `[32]byte` `,omitempty` — always emitted as a number array.
    pub target_lock_proof_sha256: [u8; 32],
    /// `time.Time` `,omitempty` — always emitted.
    #[serde(with = "wire::rfc3339")]
    pub target_locked_at: OffsetDateTime,
    #[serde(
        rename = "fixture_load_elapsed",
        default,
        skip_serializing_if = "duration_is_zero",
        serialize_with = "ser_duration_ns",
        deserialize_with = "de_duration_ns"
    )]
    pub fixture_load_elapsed: time::Duration,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provision_receipt_binding: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub minio_seed_binding: String,
    #[serde(with = "wire::rfc3339")]
    pub fixture_loaded_at: OffsetDateTime,
}

/// `backupThroughputLaunchRecord` — on-disk shape. `,omitempty`
/// never applies to `time.Time`/`[32]byte`, so the zero values are
/// always emitted, matching upstream byte-for-byte.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupThroughputLaunchRecord {
    pub schema_version: String,
    pub launch_evidence_id: Uuid,
    pub supervisor_launch_id: Uuid,
    pub operation_id: Uuid,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub peer_pid: i32,
    pub process_start: String,
    pub executable: String,
    pub mode: String,
    pub repository_binding: RepositoryBindingJournalWire,
    pub static_binding: BackupThroughputStaticBinding,
    #[serde(with = "wire::rfc3339")]
    pub accepted_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub deadline: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub issued_at: OffsetDateTime,
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_fingerprint: String,
    pub target_lock_proof_sha256: [u8; 32],
    #[serde(with = "wire::rfc3339")]
    pub target_locked_at: OffsetDateTime,
    #[serde(
        rename = "fixture_load_elapsed",
        skip_serializing_if = "duration_is_zero",
        serialize_with = "ser_duration_ns",
        deserialize_with = "de_duration_ns",
        default
    )]
    pub fixture_load_elapsed: time::Duration,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provision_receipt_binding: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub minio_seed_binding: String,
    #[serde(with = "wire::rfc3339")]
    pub fixture_loaded_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub staged_evidence_digest: String,
    #[serde(with = "wire::rfc3339")]
    pub measurement_staged_at: OffsetDateTime,
    pub nonce: String,
    pub hmac: String,
}

impl Default for BackupThroughputLaunchRecord {
    fn default() -> Self {
        Self {
            schema_version: String::new(),
            launch_evidence_id: Uuid::nil(),
            supervisor_launch_id: Uuid::nil(),
            operation_id: Uuid::nil(),
            peer_uid: 0,
            peer_gid: 0,
            peer_pid: 0,
            process_start: String::new(),
            executable: String::new(),
            mode: String::new(),
            repository_binding: RepositoryBindingJournalWire::default(),
            static_binding: BackupThroughputStaticBinding::default(),
            accepted_at: wire::go_zero_time(),
            deadline: wire::go_zero_time(),
            issued_at: wire::go_zero_time(),
            state: String::new(),
            target_fingerprint: String::new(),
            target_lock_proof_sha256: [0u8; 32],
            target_locked_at: wire::go_zero_time(),
            fixture_load_elapsed: time::Duration::ZERO,
            provision_receipt_binding: String::new(),
            minio_seed_binding: String::new(),
            fixture_loaded_at: wire::go_zero_time(),
            staged_evidence_digest: String::new(),
            measurement_staged_at: wire::go_zero_time(),
            nonce: String::new(),
            hmac: String::new(),
        }
    }
}

impl BackupThroughputLaunchRecord {
    /// `record.authority()`.
    fn authority(&self) -> BackupThroughputLaunchAuthority {
        BackupThroughputLaunchAuthority {
            launch_evidence_id: self.launch_evidence_id,
            operation_id: self.operation_id,
            deadline: self.deadline,
        }
    }

    /// `record.status()`.
    fn status(&self) -> BackupThroughputLaunchStatus {
        BackupThroughputLaunchStatus {
            supervisor_launch_id: self.supervisor_launch_id,
            launch_evidence_id: self.launch_evidence_id,
            operation_id: self.operation_id,
            repository_binding_id: self.repository_binding.binding_id,
            phase: self.state.clone(),
            target_fingerprint: self.target_fingerprint.clone(),
            target_lock_proof_sha256: self.target_lock_proof_sha256,
            target_locked_at: self.target_locked_at,
            fixture_load_elapsed: self.fixture_load_elapsed,
            provision_receipt_binding: self.provision_receipt_binding.clone(),
            minio_seed_binding: self.minio_seed_binding.clone(),
            fixture_loaded_at: self.fixture_loaded_at,
        }
    }
}

fn payload(record: &BackupThroughputLaunchRecord) -> Result<Vec<u8>, Failure> {
    let mut r = record.clone();
    r.hmac.clear();
    serde_json::to_vec(&r).map_err(|_| unavailable())
}

fn binding_eq(
    record_binding: &RepositoryBindingJournalWire,
    evidence_binding: &RepositoryBindingJournalWire,
) -> bool {
    binding_from_wire(record_binding)
        .map(|r| {
            binding_from_wire(evidence_binding)
                .map(|e| r == e)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// `validBackupThroughputLaunchProgress`.
fn valid_launch_progress(record: &BackupThroughputLaunchRecord) -> bool {
    let target_empty = record.target_fingerprint.is_empty()
        && record.target_lock_proof_sha256 == [0u8; 32]
        && wire::is_go_zero_time(record.target_locked_at);
    let fixture_empty = record.fixture_load_elapsed.is_zero()
        && record.provision_receipt_binding.is_empty()
        && record.minio_seed_binding.is_empty()
        && wire::is_go_zero_time(record.fixture_loaded_at);
    let stage_empty = record.staged_evidence_digest.is_empty()
        && wire::is_go_zero_time(record.measurement_staged_at);
    let target_valid = || -> bool {
        record
            .static_binding
            .with_target_fingerprint(&record.target_fingerprint)
            .is_ok()
            && record.target_lock_proof_sha256 != [0u8; 32]
            && record.target_locked_at >= record.issued_at
            && record.target_locked_at < record.deadline
    };
    let fixture_valid = || -> bool {
        target_valid()
            && record.fixture_load_elapsed > time::Duration::ZERO
            && wire::valid_prefixed_sha256(&record.provision_receipt_binding)
            && wire::valid_prefixed_sha256(&record.minio_seed_binding)
            && record.fixture_loaded_at >= record.target_locked_at
            && record.fixture_loaded_at < record.deadline
            && record.fixture_load_elapsed <= record.fixture_loaded_at - record.accepted_at
    };
    match record.state.as_str() {
        s if s == BACKUP_THROUGHPUT_LAUNCH_ISSUED || s == BACKUP_THROUGHPUT_LAUNCH_ACTIVE => {
            target_empty && fixture_empty && stage_empty
        }
        s if s == BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED => {
            target_valid() && fixture_empty && stage_empty
        }
        s if s == BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED => fixture_valid() && stage_empty,
        s if s == BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED => {
            fixture_valid()
                && wire::valid_prefixed_sha256(&record.staged_evidence_digest)
                && record.measurement_staged_at >= record.fixture_loaded_at
                && record.measurement_staged_at < record.deadline
        }
        _ => false,
    }
}

/// `backupThroughputLaunchStore`.
pub struct BackupThroughputLaunchStore {
    root: PathBuf,
    signing: Arc<SigningService>,
    journal: Arc<RecoveryJournalStore>,
    throughput: Arc<ThroughputJournalStore>,
    payloads: Arc<PayloadEpochStore>,
    runtime_uid: u32,
    runtime_gid: u32,
    executable: String,
}

impl BackupThroughputLaunchStore {
    /// `newBackupThroughputLaunchStore`.
    pub fn new(
        broker_root: &Path,
        signing: Arc<SigningService>,
        journal: Arc<RecoveryJournalStore>,
        throughput: Arc<ThroughputJournalStore>,
        payloads: Arc<PayloadEpochStore>,
        runtime_uid: u32,
        runtime_gid: u32,
    ) -> Result<Self, Failure> {
        Self::with_executable(
            broker_root,
            signing,
            journal,
            throughput,
            payloads,
            runtime_uid,
            runtime_gid,
            BACKUP_THROUGHPUT_WORKER_EXECUTABLE,
        )
    }

    /// `newBackupThroughputLaunchStoreWithExecutable`.
    #[allow(clippy::too_many_arguments)] // upstream parity signature
    pub fn with_executable(
        broker_root: &Path,
        signing: Arc<SigningService>,
        journal: Arc<RecoveryJournalStore>,
        throughput: Arc<ThroughputJournalStore>,
        payloads: Arc<PayloadEpochStore>,
        runtime_uid: u32,
        runtime_gid: u32,
        executable: &str,
    ) -> Result<Self, Failure> {
        if broker_root.as_os_str().is_empty() || !Path::new(executable).is_absolute() {
            return Err(unavailable());
        }
        let root = broker_root.join(BACKUP_THROUGHPUT_LAUNCH_DIRECTORY);
        durable::mkdir_p(&root, durable::PRIVATE_DIRECTORY_MODE).map_err(|_| unavailable())?;
        durable::validate_private_directory(&root, "backup throughput launch root")
            .map_err(|_| unavailable())?;
        Ok(Self {
            root,
            signing,
            journal,
            throughput,
            payloads,
            runtime_uid,
            runtime_gid,
            executable: executable.to_string(),
        })
    }

    fn path(&self, operation_id: Uuid) -> PathBuf {
        self.root.join(format!("{operation_id}.json"))
    }

    fn lock_path(&self, path: &Path) -> Result<std::os::fd::OwnedFd, Failure> {
        durable::open_lock(path).map_err(|_| unavailable())
    }

    /// `Issue` — binds the exact live probe worker.
    pub fn issue(
        &self,
        evidence: &BackupThroughputLaunchEvidence,
    ) -> Result<BackupThroughputLaunchAuthority, Failure> {
        if evidence.supervisor_launch_id.is_nil()
            || evidence.operation_id.is_nil()
            || !is_v7(evidence.operation_id)
            || evidence.pid <= 0
            || evidence.process_start.is_empty()
            || evidence.executable != self.executable
            || evidence.mode != BACKUP_THROUGHPUT_WORKER_MODE
            || wire::is_go_zero_time(evidence.deadline)
        {
            return Err(unavailable());
        }
        let repository_binding = binding_from_wire(&evidence.repository_binding)?;
        if repository_binding.verify().is_err()
            || repository_binding.owner_uid != self.runtime_uid
            || repository_binding.owner_gid != self.runtime_gid
            || evidence.static_binding.validate().is_err()
            || evidence.static_binding.repository_binding_id != repository_binding.binding_id
        {
            return Err(unavailable());
        }
        let (accepted_at, deadline) = self
            .throughput
            .accepted_context(evidence.operation_id)
            .map_err(|_| unavailable())?;
        let now = OffsetDateTime::now_utc();
        if deadline != evidence.deadline.to_offset(time::UtcOffset::UTC)
            || deadline > accepted_at + MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || now >= deadline
        {
            return Err(unavailable());
        }
        let active_payload = self.payloads.read_active().map_err(|_| unavailable())?;
        if active_payload != evidence.static_binding.payload_epoch_id {
            return Err(unavailable());
        }
        let (_generation, minio_receipt) = self
            .journal
            .resolve_bound_minio_handoff(evidence.operation_id, Purpose::MinioBackup)
            .map_err(|_| unavailable())?;
        if minio_receipt.policy_digest != evidence.static_binding.minio_backup_policy_digest
            || minio_receipt.bucket != CENTRAL_ARTIFACTS_BUCKET
            || minio_receipt.key_prefix != MINIO_BACKUP_KEY_SCOPE
            || minio_receipt.expires_at < deadline
        {
            return Err(unavailable());
        }
        let (executable, process_start) =
            verify_peer_process(evidence.pid).map_err(|_| unavailable())?;
        if executable != evidence.executable || process_start != evidence.process_start {
            return Err(unavailable());
        }
        let mut nonce = [0u8; 32];
        rustix::rand::getrandom(&mut nonce, rustix::rand::GetRandomFlags::empty())
            .map_err(|_| unavailable())?;
        let launch_id = Uuid::now_v7();
        let path = self.path(evidence.operation_id);
        let _lock = self.lock_path(&path)?;
        let mut record = BackupThroughputLaunchRecord {
            schema_version: BACKUP_THROUGHPUT_LAUNCH_SCHEMA.to_string(),
            launch_evidence_id: launch_id,
            supervisor_launch_id: evidence.supervisor_launch_id,
            operation_id: evidence.operation_id,
            peer_uid: self.runtime_uid,
            peer_gid: self.runtime_gid,
            peer_pid: evidence.pid,
            process_start: process_start.clone(),
            executable: executable.clone(),
            mode: evidence.mode.clone(),
            repository_binding: evidence.repository_binding.clone(),
            static_binding: evidence.static_binding.clone(),
            accepted_at,
            deadline,
            issued_at: now,
            state: BACKUP_THROUGHPUT_LAUNCH_ISSUED.to_string(),
            nonce: wire::hex_encode(&nonce),
            ..BackupThroughputLaunchRecord::default()
        };
        let payload = payload(&record)?;
        record.hmac = self
            .signing
            .fingerprint(BACKUP_THROUGHPUT_LAUNCH_HMAC_DOMAIN, &payload);
        if self.write_exclusive(&path, &record).is_err() {
            let stored = self.read(evidence.operation_id)?;
            if !same_launch_evidence(&stored, evidence, accepted_at) {
                return Err(unavailable());
            }
            return Ok(stored.authority());
        }
        Ok(record.authority())
    }

    fn write_exclusive<T: serde::Serialize>(&self, path: &Path, value: &T) -> Result<(), Failure> {
        durable::write_exclusive_json(path, value).map_err(|_| unavailable())
    }

    fn replace<T: serde::Serialize>(&self, path: &Path, value: &T) -> Result<(), Failure> {
        durable::replace_json(path, value).map_err(|_| unavailable())
    }

    /// `WorkerContext`.
    pub fn worker_context(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        peer: &PeerCred,
    ) -> Result<BackupThroughputWorkerContext, Failure> {
        let record = self.validate_worker(launch_evidence_id, operation_id, peer)?;
        Ok(BackupThroughputWorkerContext {
            launch_evidence_id: record.launch_evidence_id,
            operation_id: record.operation_id,
            phase: record.state.clone(),
            accepted_at: record.accepted_at,
            deadline: record.deadline,
            static_binding: record.static_binding.clone(),
            target_fingerprint: record.target_fingerprint.clone(),
            fixture_load_elapsed: record.fixture_load_elapsed,
            provision_receipt_binding: record.provision_receipt_binding.clone(),
        })
    }

    /// `MarkTargetLocked`.
    pub fn mark_target_locked(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        peer: &PeerCred,
        attestation: &BackupThroughputTargetLockAttestation,
    ) -> Result<(), Failure> {
        if self
            .validate_worker(launch_evidence_id, operation_id, peer)
            .is_err()
            || attestation.target_lock_proof_sha256 == [0u8; 32]
            || wire::is_go_zero_time(attestation.locked_at)
        {
            return Err(unavailable());
        }
        let path = self.path(operation_id);
        let _lock = self.lock_path(&path)?;
        let mut record = self.read(operation_id)?;
        if record
            .static_binding
            .with_target_fingerprint(&attestation.target_fingerprint)
            .is_err()
            || record.launch_evidence_id != launch_evidence_id
            || attestation.locked_at < record.issued_at
            || attestation.locked_at >= record.deadline
            || attestation.locked_at > OffsetDateTime::now_utc() + time::Duration::seconds(1)
        {
            return Err(unavailable());
        }
        if record.state == BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED
            || record.state == BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED
            || record.state == BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED
        {
            if record.target_fingerprint != attestation.target_fingerprint
                || record.target_lock_proof_sha256 != attestation.target_lock_proof_sha256
                || record.target_locked_at != attestation.locked_at.to_offset(time::UtcOffset::UTC)
            {
                return Err(unavailable());
            }
            return Ok(());
        }
        if record.state != BACKUP_THROUGHPUT_LAUNCH_ACTIVE {
            return Err(unavailable());
        }
        record.state = BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED.to_string();
        record.target_fingerprint = attestation.target_fingerprint.clone();
        record.target_lock_proof_sha256 = attestation.target_lock_proof_sha256;
        record.target_locked_at = attestation.locked_at.to_offset(time::UtcOffset::UTC);
        self.sign(&mut record)?;
        self.replace(&path, &record)
    }

    /// `ReadState` — reconciles `fixture_loaded` with a staged
    /// measurement that arrived while the state file was locked.
    pub fn read_state(
        &self,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
    ) -> Result<BackupThroughputLaunchStatus, Failure> {
        if operation_id.is_nil() || launch_evidence_id.is_nil() {
            return Err(unavailable());
        }
        let path = self.path(operation_id);
        let _lock = self.lock_path(&path)?;
        let mut record = self.read(operation_id)?;
        if record.launch_evidence_id != launch_evidence_id {
            return Err(unavailable());
        }
        if record.state == BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED
            && let Ok((pending, staged_at)) = self.throughput.pending_measurement(operation_id)
            && pending.probe_started_at == record.accepted_at
            && pending.fixture_load_elapsed == record.fixture_load_elapsed
            && pending.binding().target_fingerprint == record.target_fingerprint
            && static_backup_throughput_binding(pending.binding()) == record.static_binding
        {
            let digest = throughput_evidence_digest(&pending)?;
            record.state = BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED.to_string();
            record.staged_evidence_digest = digest;
            record.measurement_staged_at = staged_at;
            self.sign(&mut record)?;
            self.replace(&path, &record)?;
        }
        Ok(record.status())
    }

    /// `RootState` — the operator's view without the worker's launch
    /// evidence identity.
    pub fn root_state(&self, operation_id: Uuid) -> Result<BackupThroughputLaunchStatus, Failure> {
        if operation_id.is_nil() {
            return Err(unavailable());
        }
        let path = self.path(operation_id);
        let lock = self.lock_path(&path)?;
        let record = self.read(operation_id);
        durable::unlock_and_close(lock);
        let record = record?;
        self.read_state(operation_id, record.launch_evidence_id)
    }

    /// `MarkFixtureLoaded`.
    pub fn mark_fixture_loaded(
        &self,
        operation_id: Uuid,
        launch_evidence_id: Uuid,
        attestation: &BackupThroughputFixtureLoadAttestation,
    ) -> Result<(), Failure> {
        if operation_id.is_nil()
            || launch_evidence_id.is_nil()
            || attestation.fixture_load_elapsed <= time::Duration::ZERO
            || !wire::valid_prefixed_sha256(&attestation.provision_receipt_binding)
            || !wire::valid_prefixed_sha256(&attestation.minio_seed_binding)
            || wire::is_go_zero_time(attestation.loaded_at)
        {
            return Err(unavailable());
        }
        let path = self.path(operation_id);
        let _lock = self.lock_path(&path)?;
        let mut record = self.read(operation_id)?;
        if record.launch_evidence_id != launch_evidence_id
            || attestation.loaded_at < record.target_locked_at
            || attestation.loaded_at >= record.deadline
            || attestation.fixture_load_elapsed > attestation.loaded_at - record.accepted_at
        {
            return Err(unavailable());
        }
        if record.state == BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED
            || record.state == BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED
        {
            if record.fixture_load_elapsed != attestation.fixture_load_elapsed
                || record.provision_receipt_binding != attestation.provision_receipt_binding
                || record.minio_seed_binding != attestation.minio_seed_binding
                || record.fixture_loaded_at != attestation.loaded_at.to_offset(time::UtcOffset::UTC)
            {
                return Err(unavailable());
            }
            return Ok(());
        }
        if record.state != BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED {
            return Err(unavailable());
        }
        record.state = BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED.to_string();
        record.fixture_load_elapsed = attestation.fixture_load_elapsed;
        record.provision_receipt_binding = attestation.provision_receipt_binding.clone();
        record.minio_seed_binding = attestation.minio_seed_binding.clone();
        record.fixture_loaded_at = attestation.loaded_at.to_offset(time::UtcOffset::UTC);
        self.sign(&mut record)?;
        self.replace(&path, &record)
    }

    /// `StageMeasurement` — binds the staged evidence into the launch
    /// record after the journal accepts it.
    pub fn stage_measurement(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        peer: &PeerCred,
        evidence: &ThroughputEvidence,
        staged_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        let record = self.validate_worker(launch_evidence_id, operation_id, peer)?;
        if wire::is_go_zero_time(staged_at)
            || evidence.probe_operation_id != operation_id
            || evidence.probe_started_at.to_offset(time::UtcOffset::UTC) != record.accepted_at
            || evidence.fixture_load_elapsed != record.fixture_load_elapsed
            || evidence.binding().target_fingerprint != record.target_fingerprint
            || static_backup_throughput_binding(evidence.binding()) != record.static_binding
        {
            return Err(unavailable());
        }
        let mut normalized = evidence.clone();
        normalized.probe_started_at = normalized.probe_started_at.to_offset(time::UtcOffset::UTC);
        normalized.probe_completed_at = normalized
            .probe_completed_at
            .to_offset(time::UtcOffset::UTC);
        normalized.measured_at = normalized.measured_at.to_offset(time::UtcOffset::UTC);
        normalized.expires_at = normalized.expires_at.to_offset(time::UtcOffset::UTC);
        normalized.cleanup_verified_at = normalized
            .cleanup_verified_at
            .to_offset(time::UtcOffset::UTC);
        let digest = throughput_evidence_digest(&normalized)?;
        let path = self.path(operation_id);
        let _lock = self.lock_path(&path)?;
        let mut record = self.read(operation_id)?;
        if record.launch_evidence_id != launch_evidence_id {
            return Err(unavailable());
        }
        if record.state == BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED {
            if record.staged_evidence_digest != digest
                || record.measurement_staged_at != staged_at.to_offset(time::UtcOffset::UTC)
            {
                return Err(unavailable());
            }
            return self
                .throughput
                .stage_measurement(operation_id, normalized, staged_at);
        }
        if record.state != BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED
            || staged_at < record.fixture_loaded_at
            || staged_at >= record.deadline
        {
            return Err(unavailable());
        }
        self.throughput
            .stage_measurement(operation_id, normalized, staged_at)?;
        record.state = BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED.to_string();
        record.staged_evidence_digest = digest;
        record.measurement_staged_at = staged_at.to_offset(time::UtcOffset::UTC);
        self.sign(&mut record)?;
        self.replace(&path, &record)
    }

    /// `validateWorker` — peer credential + live process + journal
    /// acceptance-window binding; flips `issued` → `active`.
    pub(crate) fn validate_worker(
        &self,
        launch_evidence_id: Uuid,
        operation_id: Uuid,
        peer: &PeerCred,
    ) -> Result<BackupThroughputLaunchRecord, Failure> {
        if launch_evidence_id.is_nil()
            || operation_id.is_nil()
            || peer.pid.as_raw_pid() <= 0
            || peer.uid.as_raw() != self.runtime_uid
            || peer.gid.as_raw() != self.runtime_gid
        {
            return Err(unavailable());
        }
        let path = self.path(operation_id);
        let _lock = self.lock_path(&path)?;
        let mut record = self.read(operation_id)?;
        if record.launch_evidence_id != launch_evidence_id
            || record.peer_uid != peer.uid.as_raw()
            || record.peer_gid != peer.gid.as_raw()
            || record.peer_pid != peer.pid.as_raw_pid()
            || OffsetDateTime::now_utc() >= record.deadline
        {
            return Err(unavailable());
        }
        let (executable, process_start) =
            verify_peer_process(peer.pid.as_raw_pid()).map_err(|_| unavailable())?;
        if executable != record.executable || process_start != record.process_start {
            return Err(unavailable());
        }
        let (accepted_at, deadline) = self
            .throughput
            .accepted_context(operation_id)
            .map_err(|_| unavailable())?;
        if accepted_at != record.accepted_at || deadline != record.deadline {
            return Err(unavailable());
        }
        if record.state == BACKUP_THROUGHPUT_LAUNCH_ISSUED {
            record.state = BACKUP_THROUGHPUT_LAUNCH_ACTIVE.to_string();
            self.sign(&mut record)?;
            self.replace(&path, &record)?;
        }
        Ok(record)
    }

    /// `read` — strict decode + validation + HMAC.
    fn read(&self, operation_id: Uuid) -> Result<BackupThroughputLaunchRecord, Failure> {
        if operation_id.is_nil() {
            return Err(unavailable());
        }
        let record: BackupThroughputLaunchRecord =
            read_private_json(&self.path(operation_id)).map_err(|_| unavailable())?;
        if self.validate_record(&record).is_err() {
            return Err(unavailable());
        }
        let p = payload(&record)?;
        let want = self
            .signing
            .fingerprint(BACKUP_THROUGHPUT_LAUNCH_HMAC_DOMAIN, &p);
        if !wire::hmac_equal(record.hmac.as_bytes(), want.as_bytes()) {
            return Err(unavailable());
        }
        Ok(record)
    }

    /// `validateRecord`.
    fn validate_record(&self, record: &BackupThroughputLaunchRecord) -> Result<(), Failure> {
        let nonce_ok = wire::hex_decode(&record.nonce)
            .map(|n| n.len() == 32)
            .unwrap_or(false);
        if record.schema_version != BACKUP_THROUGHPUT_LAUNCH_SCHEMA
            || record.launch_evidence_id.is_nil()
            || !is_v7(record.launch_evidence_id)
            || record.supervisor_launch_id.is_nil()
            || record.operation_id.is_nil()
            || !is_v7(record.operation_id)
            || record.peer_uid != self.runtime_uid
            || record.peer_gid != self.runtime_gid
            || record.peer_pid <= 0
            || record.process_start.is_empty()
            || record.executable != self.executable
            || record.mode != BACKUP_THROUGHPUT_WORKER_MODE
            || !nonce_ok
        {
            return Err(unavailable());
        }
        let repository_binding = binding_from_wire(&record.repository_binding)?;
        if repository_binding.verify().is_err()
            || repository_binding.owner_uid != self.runtime_uid
            || repository_binding.owner_gid != self.runtime_gid
            || record.static_binding.validate().is_err()
            || record.static_binding.repository_binding_id != repository_binding.binding_id
            || wire::is_go_zero_time(record.accepted_at)
            || wire::is_go_zero_time(record.deadline)
            || record.accepted_at >= record.deadline
            || record.deadline > record.accepted_at + MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || record.issued_at < record.accepted_at
            || record.issued_at >= record.deadline
            || !valid_launch_progress(record)
        {
            return Err(unavailable());
        }
        Ok(())
    }

    /// `signRecord`.
    fn sign(&self, record: &mut BackupThroughputLaunchRecord) -> Result<(), Failure> {
        let p = payload(record)?;
        record.hmac = self
            .signing
            .fingerprint(BACKUP_THROUGHPUT_LAUNCH_HMAC_DOMAIN, &p);
        Ok(())
    }
}

/// `sameBackupThroughputLaunchEvidence`.
fn same_launch_evidence(
    record: &BackupThroughputLaunchRecord,
    evidence: &BackupThroughputLaunchEvidence,
    accepted_at: OffsetDateTime,
) -> bool {
    record.supervisor_launch_id == evidence.supervisor_launch_id
        && record.operation_id == evidence.operation_id
        && record.peer_pid == evidence.pid
        && record.process_start == evidence.process_start
        && record.executable == evidence.executable
        && record.mode == evidence.mode
        && binding_eq(&record.repository_binding, &evidence.repository_binding)
        && record.static_binding == evidence.static_binding
        && record.accepted_at == accepted_at.to_offset(time::UtcOffset::UTC)
        && record.deadline == evidence.deadline.to_offset(time::UtcOffset::UTC)
}
