//! `throughputJournalStore` — the crash-safe throughput evidence
//! journal. Port of upstream `throughput_journal.go`: a single
//! `<broker_root>/backup-throughput` directory, one
//! `operations/<uuid>.json` record per probe operation, and an
//! `active-receipt.json` selector. `state.lock` serializes every
//! mutation; the selector is always published after the operation
//! record so a crash between the two leaves a recoverable cut point
//! the read paths detect deterministically.
//!
//! Wire and digest behavior is byte-for-byte upstream compatible:
//! operation and selector records are HMAC-authenticated over the
//! canonical JSON encoding (PascalCase `backup.ThroughputEvidence`
//! fields, nanosecond durations), and every decode is strict.

use std::path::PathBuf;

use central_backup::backup::capacity::{
    MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES, MAXIMUM_THROUGHPUT_PROBE_ELAPSED,
    MINIMUM_DUMP_PROBE_ARCHIVE_BYTES, OBJECT_PROBE_PAYLOAD_BYTES, RecoveryProfile,
};
use central_backup::recovery::profile::{
    BACKUP_THROUGHPUT_CLEANUP_CLEAN, BACKUP_THROUGHPUT_RECEIPT_SCHEMA, ThroughputEvidence,
};
use central_foundation::failure::Failure;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::durable;
use super::recovery_journal::{generation_key, read_private_json};
use super::signing::SigningService;
use super::wire;
use std::sync::Arc;

const THROUGHPUT_JOURNAL_DIRECTORY: &str = "backup-throughput";
const THROUGHPUT_OPERATION_DIRECTORY: &str = "operations";
const THROUGHPUT_ACTIVE_FILENAME: &str = "active-receipt.json";
const THROUGHPUT_LOCK_FILENAME: &str = "state.lock";
const THROUGHPUT_OPERATION_SCHEMA: &str = "central.backup-throughput-operation/v1";
const THROUGHPUT_ACTIVE_SCHEMA: &str = "central.backup-throughput-active/v1";
const THROUGHPUT_CLEANUP_SCHEMA: &str = "central.backup-throughput-cleanup-attestation/v1";
const THROUGHPUT_CLEANUP_RESOLUTION_SCHEMA: &str =
    "central.backup-throughput-cleanup-resolution/v1";
const THROUGHPUT_OPERATION_HMAC_DOMAIN: &str = "slice-c-backup-throughput-operation-v1";
const THROUGHPUT_ACTIVE_HMAC_DOMAIN: &str = "slice-c-backup-throughput-active-v1";
const THROUGHPUT_PHASE_ACCEPTED: &str = "accepted";
const THROUGHPUT_PHASE_MEASUREMENT_PENDING: &str = "measurement_pending";
const THROUGHPUT_PHASE_COMPLETION_PENDING: &str = "completion_pending";
const THROUGHPUT_PHASE_COMPLETED: &str = "completed";
const THROUGHPUT_PHASE_FAILED: &str = "failed";
const THROUGHPUT_PHASE_CLEANUP_REQUIRED: &str = "cleanup_required";
const THROUGHPUT_MAXIMUM_RECORD_BYTES: u64 = 64 * 1024;

fn unavailable() -> Failure {
    Failure::internal(
        super::recovery_journal::JOURNAL_UNAVAILABLE_CODE,
        "broker: throughput journal unavailable",
    )
}

fn is_v7(id: Uuid) -> bool {
    id.get_version_num() == 7
}

/// `throughputCleanupCounts` — the six probe cleanup counters the
/// attestation must report as fully drained.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputCleanupCounts {
    pub live_probe_processes: u32,
    pub open_probe_descriptors: u32,
    pub postgres_sessions: u32,
    pub disposable_databases: u32,
    pub probe_objects: u32,
    pub repository_temporary_files: u32,
    pub held_permits: u32,
}

/// `throughputCleanupAttestation` — the root helper's signed-shape
/// statement that the measured probe tree has been reaped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputCleanupAttestation {
    pub schema_version: String,
    pub operation_id: Uuid,
    pub attestor_uid: u32,
    pub worker_tree_reaped: bool,
    pub counts: ThroughputCleanupCounts,
    /// `time.Duration` — nanoseconds on the wire.
    #[serde(rename = "parent_elapsed")]
    #[serde(with = "duration_ns")]
    pub parent_elapsed: time::Duration,
    #[serde(with = "wire::rfc3339")]
    pub attested_at: OffsetDateTime,
    pub digest: String,
}

/// `throughputCleanupResolution` — terminal statement that the
/// operation's cleanup state is resolved (zero counts for an
/// operation that never staged measurement state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputCleanupResolution {
    pub schema_version: String,
    pub operation_id: Uuid,
    pub attestor_uid: u32,
    pub counts: ThroughputCleanupCounts,
    #[serde(with = "wire::rfc3339")]
    pub resolved_at: OffsetDateTime,
    pub digest: String,
}

mod duration_ns {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(d: &time::Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_i64(d.whole_nanoseconds() as i64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<time::Duration, D::Error> {
        let ns = i64::deserialize(d)?;
        Ok(time::Duration::nanoseconds(ns))
    }
}

/// `ThroughputEvidenceBindingWire` — `json.Marshal` of
/// `backup.ThroughputEvidenceBinding` (PascalCase, strings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputEvidenceBindingWire {
    #[serde(rename = "InstanceID")]
    pub instance_id: Uuid,
    #[serde(rename = "PayloadEpochID")]
    pub payload_epoch_id: Uuid,
    #[serde(rename = "TargetFingerprint")]
    pub target_fingerprint: String,
    #[serde(rename = "RepositoryBindingID")]
    pub repository_binding_id: Uuid,
    #[serde(rename = "DeviceMountSetDigest")]
    pub device_mount_set_digest: String,
    #[serde(rename = "HostProfileDigest")]
    pub host_profile_digest: String,
    #[serde(rename = "DependencyProvisioningDigest")]
    pub dependency_provisioning_digest: String,
    #[serde(rename = "PostgresImageDigest")]
    pub postgres_image_digest: String,
    #[serde(rename = "MinioImageDigest")]
    pub minio_image_digest: String,
    #[serde(rename = "PGDumpToolDigest")]
    pub pg_dump_tool_digest: String,
    #[serde(rename = "PGDumpToolVersion")]
    pub pg_dump_tool_version: String,
    #[serde(rename = "ConfigDigest")]
    pub config_digest: String,
    #[serde(rename = "MinioBackupPolicyDigest")]
    pub minio_backup_policy_digest: String,
    #[serde(rename = "FixtureDigest")]
    pub fixture_digest: String,
    #[serde(rename = "TransferEnvelopeVersion")]
    pub transfer_envelope_version: String,
    #[serde(rename = "TransferEnvelopeDigest")]
    pub transfer_envelope_digest: String,
}

/// `ThroughputEvidenceWire` — the flat PascalCase encoding Go
/// produces for `backup.ThroughputEvidence` (the binding fields are
/// inlined on the Go struct, so the digest binds exactly this
/// byte shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputEvidenceWire {
    #[serde(rename = "SchemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ReceiptID")]
    pub receipt_id: Uuid,
    #[serde(rename = "ProbeOperationID")]
    pub probe_operation_id: Uuid,
    #[serde(rename = "ProbeStartedAt", with = "wire::rfc3339")]
    pub probe_started_at: OffsetDateTime,
    #[serde(rename = "ProbeCompletedAt", with = "wire::rfc3339")]
    pub probe_completed_at: OffsetDateTime,
    #[serde(rename = "ProbeElapsed", with = "duration_ns")]
    pub probe_elapsed: time::Duration,
    #[serde(rename = "MeasuredAt", with = "wire::rfc3339")]
    pub measured_at: OffsetDateTime,
    #[serde(rename = "ExpiresAt", with = "wire::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(flatten)]
    pub binding: ThroughputEvidenceBindingWire,
    #[serde(rename = "DumpArchiveBytes")]
    pub dump_archive_bytes: u64,
    #[serde(rename = "DumpWorkBytes")]
    pub dump_work_bytes: u64,
    #[serde(rename = "DumpElapsed", with = "duration_ns")]
    pub dump_elapsed: time::Duration,
    #[serde(rename = "FixtureLoadElapsed", with = "duration_ns")]
    pub fixture_load_elapsed: time::Duration,
    #[serde(rename = "DumpBytesPerSec")]
    pub dump_bytes_per_sec: u64,
    #[serde(rename = "ObjectPayloadBytes")]
    pub object_payload_bytes: u64,
    #[serde(rename = "ObjectWorkBytes")]
    pub object_work_bytes: u64,
    #[serde(rename = "ObjectElapsed", with = "duration_ns")]
    pub object_elapsed: time::Duration,
    #[serde(rename = "ObjectBytesPerSec")]
    pub object_bytes_per_sec: u64,
    #[serde(rename = "CleanupState")]
    pub cleanup_state: String,
    #[serde(rename = "CleanupVerifiedAt", with = "wire::rfc3339")]
    pub cleanup_verified_at: OffsetDateTime,
}

pub(crate) fn evidence_to_wire(e: &ThroughputEvidence) -> ThroughputEvidenceWire {
    let b = e.binding();
    ThroughputEvidenceWire {
        schema_version: e.schema_version.clone(),
        receipt_id: e.receipt_id,
        probe_operation_id: e.probe_operation_id,
        probe_started_at: e.probe_started_at,
        probe_completed_at: e.probe_completed_at,
        probe_elapsed: e.probe_elapsed,
        measured_at: e.measured_at,
        expires_at: e.expires_at,
        binding: ThroughputEvidenceBindingWire {
            instance_id: b.instance_id,
            payload_epoch_id: b.payload_epoch_id,
            target_fingerprint: b.target_fingerprint.clone(),
            repository_binding_id: b.repository_binding_id,
            device_mount_set_digest: b.device_mount_set_digest.clone(),
            host_profile_digest: b.host_profile_digest.clone(),
            dependency_provisioning_digest: b.dependency_provisioning_digest.clone(),
            postgres_image_digest: b.postgres_image_digest.clone(),
            minio_image_digest: b.minio_image_digest.clone(),
            pg_dump_tool_digest: b.pg_dump_tool_digest.clone(),
            pg_dump_tool_version: b.pg_dump_tool_version.clone(),
            config_digest: b.config_digest.clone(),
            minio_backup_policy_digest: b.minio_backup_policy_digest.clone(),
            fixture_digest: b.fixture_digest.clone(),
            transfer_envelope_version: b.transfer_envelope_version.clone(),
            transfer_envelope_digest: b.transfer_envelope_digest.clone(),
        },
        dump_archive_bytes: e.dump_archive_bytes,
        dump_work_bytes: e.dump_work_bytes,
        dump_elapsed: e.dump_elapsed,
        fixture_load_elapsed: e.fixture_load_elapsed,
        dump_bytes_per_sec: e.dump_bytes_per_sec,
        object_payload_bytes: e.object_payload_bytes,
        object_work_bytes: e.object_work_bytes,
        object_elapsed: e.object_elapsed,
        object_bytes_per_sec: e.object_bytes_per_sec,
        cleanup_state: e.cleanup_state.clone(),
        cleanup_verified_at: e.cleanup_verified_at,
    }
}

pub(crate) fn evidence_from_wire(w: &ThroughputEvidenceWire) -> ThroughputEvidence {
    use central_backup::recovery::profile::ThroughputEvidenceBinding;
    ThroughputEvidence {
        schema_version: w.schema_version.clone(),
        receipt_id: w.receipt_id,
        probe_operation_id: w.probe_operation_id,
        probe_started_at: w.probe_started_at,
        probe_completed_at: w.probe_completed_at,
        probe_elapsed: w.probe_elapsed,
        measured_at: w.measured_at,
        expires_at: w.expires_at,
        binding: ThroughputEvidenceBinding {
            instance_id: w.binding.instance_id,
            payload_epoch_id: w.binding.payload_epoch_id,
            target_fingerprint: w.binding.target_fingerprint.clone(),
            repository_binding_id: w.binding.repository_binding_id,
            device_mount_set_digest: w.binding.device_mount_set_digest.clone(),
            host_profile_digest: w.binding.host_profile_digest.clone(),
            dependency_provisioning_digest: w.binding.dependency_provisioning_digest.clone(),
            postgres_image_digest: w.binding.postgres_image_digest.clone(),
            minio_image_digest: w.binding.minio_image_digest.clone(),
            pg_dump_tool_digest: w.binding.pg_dump_tool_digest.clone(),
            pg_dump_tool_version: w.binding.pg_dump_tool_version.clone(),
            config_digest: w.binding.config_digest.clone(),
            minio_backup_policy_digest: w.binding.minio_backup_policy_digest.clone(),
            fixture_digest: w.binding.fixture_digest.clone(),
            transfer_envelope_version: w.binding.transfer_envelope_version.clone(),
            transfer_envelope_digest: w.binding.transfer_envelope_digest.clone(),
        },
        dump_archive_bytes: w.dump_archive_bytes,
        dump_work_bytes: w.dump_work_bytes,
        dump_elapsed: w.dump_elapsed,
        fixture_load_elapsed: w.fixture_load_elapsed,
        dump_bytes_per_sec: w.dump_bytes_per_sec,
        object_payload_bytes: w.object_payload_bytes,
        object_work_bytes: w.object_work_bytes,
        object_elapsed: w.object_elapsed,
        object_bytes_per_sec: w.object_bytes_per_sec,
        cleanup_state: w.cleanup_state.clone(),
        cleanup_verified_at: w.cleanup_verified_at,
    }
}

/// `throughputOperationRecord` — the durable operation record.
/// `selector_phase` is `json:"-"` upstream: a read-side annotation of
/// which phase the selector last published, never persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputOperationRecord {
    pub schema_version: String,
    pub operation_id: Uuid,
    pub phase: String,
    pub revision: u64,
    #[serde(with = "wire::rfc3339")]
    pub accepted_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub deadline: OffsetDateTime,
    /// `time.Time` `,omitempty` — always emitted (zero time included).
    #[serde(with = "wire::rfc3339")]
    pub measurement_staged_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub activated_at: OffsetDateTime,
    #[serde(with = "wire::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ThroughputEvidenceWire>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cleanup")]
    pub cleanup: Option<ThroughputCleanupAttestation>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "cleanup_resolution"
    )]
    pub resolution: Option<ThroughputCleanupResolution>,
    pub hmac: String,
    #[serde(skip)]
    pub selector_phase: String,
}

impl Default for ThroughputOperationRecord {
    fn default() -> Self {
        Self {
            schema_version: String::new(),
            operation_id: Uuid::nil(),
            phase: String::new(),
            revision: 0,
            accepted_at: wire::go_zero_time(),
            deadline: wire::go_zero_time(),
            measurement_staged_at: wire::go_zero_time(),
            activated_at: wire::go_zero_time(),
            updated_at: wire::go_zero_time(),
            evidence: None,
            cleanup: None,
            resolution: None,
            hmac: String::new(),
            selector_phase: String::new(),
        }
    }
}

/// `throughputActiveRecord` — the selector pointing at the current
/// attempt (and, once activated, at the live receipt digest).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThroughputActiveRecord {
    pub schema_version: String,
    pub operation_id: Uuid,
    pub phase: String,
    pub revision: u64,
    #[serde(with = "wire::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub receipt_digest: String,
    pub hmac: String,
}

impl Default for ThroughputActiveRecord {
    fn default() -> Self {
        Self {
            schema_version: String::new(),
            operation_id: Uuid::nil(),
            phase: String::new(),
            revision: 0,
            updated_at: wire::go_zero_time(),
            receipt_digest: String::new(),
            hmac: String::new(),
        }
    }
}

/// `throughputMeasuredRate` — bytes/second with overflow guard.
fn throughput_measured_rate(bytes: u64, elapsed: time::Duration) -> Option<u64> {
    const SECOND_NS: u64 = 1_000_000_000;
    if bytes == 0 || elapsed <= time::Duration::ZERO || bytes > u64::MAX / SECOND_NS {
        return None;
    }
    Some(bytes * SECOND_NS / elapsed.whole_nanoseconds().max(1) as u64)
}

/// `throughputEvidenceDigest` — `sha256:` of the canonical evidence
/// JSON (PascalCase, nanosecond durations — byte-compatible with
/// `json.Marshal(backup.ThroughputEvidence)`).
pub(crate) fn throughput_evidence_digest(evidence: &ThroughputEvidence) -> Result<String, Failure> {
    let payload = serde_json::to_vec(&evidence_to_wire(evidence)).map_err(|_| unavailable())?;
    Ok(wire::sha256_prefixed(&payload))
}

/// `newThroughputCleanupAttestation`.
pub fn new_throughput_cleanup_attestation(
    operation_id: Uuid,
    attested_at: OffsetDateTime,
    parent_elapsed: time::Duration,
    worker_tree_reaped: bool,
    counts: ThroughputCleanupCounts,
) -> Result<ThroughputCleanupAttestation, Failure> {
    let mut attestation = ThroughputCleanupAttestation {
        schema_version: THROUGHPUT_CLEANUP_SCHEMA.to_string(),
        operation_id,
        attestor_uid: 0,
        worker_tree_reaped,
        counts,
        parent_elapsed,
        attested_at: attested_at.to_offset(time::UtcOffset::UTC),
        digest: String::new(),
    };
    let payload = serde_json::to_vec(&attestation).map_err(|_| unavailable())?;
    attestation.digest = wire::sha256_prefixed(&payload);
    Ok(attestation)
}

/// `newThroughputCleanupResolution`.
pub fn new_throughput_cleanup_resolution(
    operation_id: Uuid,
    counts: ThroughputCleanupCounts,
    resolved_at: OffsetDateTime,
) -> Result<ThroughputCleanupResolution, Failure> {
    let mut resolution = ThroughputCleanupResolution {
        schema_version: THROUGHPUT_CLEANUP_RESOLUTION_SCHEMA.to_string(),
        operation_id,
        attestor_uid: 0,
        counts,
        resolved_at: resolved_at.to_offset(time::UtcOffset::UTC),
        digest: String::new(),
    };
    let payload = serde_json::to_vec(&resolution).map_err(|_| unavailable())?;
    resolution.digest = wire::sha256_prefixed(&payload);
    Ok(resolution)
}

fn attestation_payload(attestation: &ThroughputCleanupAttestation) -> Result<Vec<u8>, Failure> {
    let mut a = attestation.clone();
    a.digest.clear();
    serde_json::to_vec(&a).map_err(|_| unavailable())
}

fn resolution_payload(resolution: &ThroughputCleanupResolution) -> Result<Vec<u8>, Failure> {
    let mut r = resolution.clone();
    r.digest.clear();
    serde_json::to_vec(&r).map_err(|_| unavailable())
}

/// `validateThroughputCleanupAttestation`.
fn validate_throughput_cleanup_attestation(
    attestation: &ThroughputCleanupAttestation,
    record: &ThroughputOperationRecord,
    now: OffsetDateTime,
) -> Result<(), Failure> {
    if attestation.schema_version != THROUGHPUT_CLEANUP_SCHEMA
        || attestation.operation_id != record.operation_id
        || attestation.attestor_uid != 0
        || !attestation.worker_tree_reaped
        || attestation.counts != ThroughputCleanupCounts::default()
        || attestation.parent_elapsed <= time::Duration::ZERO
        || attestation.parent_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED
        || wire::is_go_zero_time(attestation.attested_at)
        || attestation.attested_at < record.measurement_staged_at
        || attestation.attested_at > record.deadline
        || attestation.attested_at > now
        || now > record.deadline
        || attestation.parent_elapsed != attestation.attested_at - record.accepted_at
        || !wire::valid_prefixed_sha256(&attestation.digest)
    {
        return Err(unavailable());
    }
    let payload = attestation_payload(attestation)?;
    if !wire::hmac_equal(
        attestation.digest.as_bytes(),
        wire::sha256_prefixed(&payload).as_bytes(),
    ) {
        return Err(unavailable());
    }
    Ok(())
}

/// `validateThroughputCleanupResolution`.
fn validate_throughput_cleanup_resolution(
    resolution: &ThroughputCleanupResolution,
    operation_id: Uuid,
) -> Result<(), Failure> {
    if resolution.schema_version != THROUGHPUT_CLEANUP_RESOLUTION_SCHEMA
        || resolution.operation_id != operation_id
        || resolution.attestor_uid != 0
        || resolution.counts != ThroughputCleanupCounts::default()
        || wire::is_go_zero_time(resolution.resolved_at)
        || !wire::valid_prefixed_sha256(&resolution.digest)
    {
        return Err(unavailable());
    }
    let payload = resolution_payload(resolution)?;
    if !wire::hmac_equal(
        resolution.digest.as_bytes(),
        wire::sha256_prefixed(&payload).as_bytes(),
    ) {
        return Err(unavailable());
    }
    Ok(())
}

/// `normalizePendingThroughputEvidence`.
fn normalize_pending_throughput_evidence(mut evidence: ThroughputEvidence) -> ThroughputEvidence {
    evidence.probe_started_at = evidence.probe_started_at.to_offset(time::UtcOffset::UTC);
    evidence.probe_completed_at = evidence.probe_completed_at.to_offset(time::UtcOffset::UTC);
    evidence.measured_at = evidence.measured_at.to_offset(time::UtcOffset::UTC);
    evidence.expires_at = evidence.expires_at.to_offset(time::UtcOffset::UTC);
    evidence.cleanup_verified_at = evidence.cleanup_verified_at.to_offset(time::UtcOffset::UTC);
    evidence
}

/// `validatePendingThroughputEvidence`.
fn validate_pending_throughput_evidence(
    evidence: &ThroughputEvidence,
    operation_id: Uuid,
    accepted_at: OffsetDateTime,
    deadline: OffsetDateTime,
    staged_at: OffsetDateTime,
    profile: &RecoveryProfile,
) -> Result<(), Failure> {
    if evidence.schema_version != BACKUP_THROUGHPUT_RECEIPT_SCHEMA
        || !evidence.receipt_id.is_nil()
        || evidence.probe_operation_id != operation_id
        || evidence.probe_operation_id.is_nil()
        || !is_v7(evidence.probe_operation_id)
        || evidence.probe_started_at != accepted_at
        || staged_at < evidence.probe_started_at
        || staged_at > deadline
        || !wire::is_go_zero_time(evidence.probe_completed_at)
        || evidence.probe_elapsed != time::Duration::ZERO
        || !wire::is_go_zero_time(evidence.measured_at)
        || !wire::is_go_zero_time(evidence.expires_at)
        || !evidence.cleanup_state.is_empty()
        || !wire::is_go_zero_time(evidence.cleanup_verified_at)
        || evidence.binding().validate().is_err()
    {
        return Err(unavailable());
    }
    let probe_elapsed = staged_at - evidence.probe_started_at;
    if probe_elapsed <= time::Duration::ZERO
        || probe_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED
        || evidence.dump_archive_bytes < MINIMUM_DUMP_PROBE_ARCHIVE_BYTES
        || evidence.dump_archive_bytes > MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES
        || evidence.dump_work_bytes != evidence.dump_archive_bytes * 2
        || evidence.object_payload_bytes != OBJECT_PROBE_PAYLOAD_BYTES
        || evidence.object_work_bytes != evidence.object_payload_bytes * 3
        || evidence.fixture_load_elapsed <= time::Duration::ZERO
        || evidence.dump_elapsed <= time::Duration::ZERO
        || evidence.object_elapsed <= time::Duration::ZERO
        || evidence.fixture_load_elapsed > probe_elapsed
        || evidence.dump_elapsed > probe_elapsed - evidence.fixture_load_elapsed
        || evidence.object_elapsed
            > probe_elapsed - evidence.fixture_load_elapsed - evidence.dump_elapsed
    {
        return Err(unavailable());
    }
    let dump_rate = throughput_measured_rate(evidence.dump_work_bytes, evidence.dump_elapsed);
    let object_rate = throughput_measured_rate(evidence.object_work_bytes, evidence.object_elapsed);
    match (dump_rate, object_rate) {
        (Some(dump), Some(object))
            if evidence.dump_bytes_per_sec == dump
                && evidence.object_bytes_per_sec == object
                && dump >= profile.min_throughput_bps
                && object >= profile.min_throughput_bps => {}
        _ => return Err(unavailable()),
    }
    Ok(())
}

/// `validateCompletionPendingRecord`.
fn validate_completion_pending_record(
    record: &ThroughputOperationRecord,
    profile: &RecoveryProfile,
) -> Result<(), Failure> {
    let Some(evidence) = record.evidence.as_ref() else {
        return Err(unavailable());
    };
    let Some(cleanup) = record.cleanup.as_ref() else {
        return Err(unavailable());
    };
    let evidence = evidence_from_wire(evidence);
    if wire::is_go_zero_time(record.measurement_staged_at)
        || evidence.probe_operation_id != record.operation_id
        || !is_v7(evidence.receipt_id)
        || cleanup.attested_at != evidence.probe_completed_at
        || evidence.valid_at(cleanup.attested_at, profile).is_err()
    {
        return Err(unavailable());
    }
    let shape = ThroughputOperationRecord {
        operation_id: record.operation_id,
        accepted_at: record.accepted_at,
        deadline: record.deadline,
        measurement_staged_at: record.measurement_staged_at,
        ..ThroughputOperationRecord::default()
    };
    validate_throughput_cleanup_attestation(cleanup, &shape, cleanup.attested_at)
}

/// `sameThroughputOperation` — canonical JSON comparison sans HMAC.
fn same_throughput_operation(
    left: &ThroughputOperationRecord,
    right: &ThroughputOperationRecord,
) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.hmac.clear();
    right.hmac.clear();
    match (serde_json::to_vec(&left), serde_json::to_vec(&right)) {
        (Ok(l), Ok(r)) => wire::hmac_equal(&l, &r),
        _ => false,
    }
}

/// `interruptedCleanupRequiredPublish`.
fn interrupted_cleanup_required_publish(
    active: &ThroughputActiveRecord,
    record: &ThroughputOperationRecord,
) -> bool {
    if record.phase != THROUGHPUT_PHASE_CLEANUP_REQUIRED
        || active.operation_id != record.operation_id
    {
        return false;
    }
    (active.phase == THROUGHPUT_PHASE_ACCEPTED && active.revision == 1 && record.revision == 2)
        || (active.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
            && active.revision == 2
            && (record.revision == 3 || record.revision == 4))
        || (active.phase == THROUGHPUT_PHASE_COMPLETION_PENDING
            && active.revision == 3
            && record.revision == 4)
}

/// `throughputJournalStore` — the protected source of truth for the
/// single current C02 attempt. Publishing accepted state fences the
/// prior receipt; reads never scan historical operations and
/// therefore cannot fall back after a crash.
pub struct ThroughputJournalStore {
    operations: PathBuf,
    active: PathBuf,
    lock_path: PathBuf,
    signing: Arc<SigningService>,
    profile: RecoveryProfile,
}

impl ThroughputJournalStore {
    /// `newThroughputJournalStore`.
    pub fn new(
        broker_root: &std::path::Path,
        signing: Arc<SigningService>,
        profile: RecoveryProfile,
    ) -> Result<Self, Failure> {
        if broker_root.as_os_str().is_empty() || profile.validate().is_err() {
            return Err(unavailable());
        }
        durable::validate_broker_owned_root(broker_root, "throughput broker root")
            .map_err(|_| unavailable())?;
        let root = broker_root.join(THROUGHPUT_JOURNAL_DIRECTORY);
        let operations = root.join(THROUGHPUT_OPERATION_DIRECTORY);
        for path in [&root, &operations] {
            durable::mkdir_p(path, durable::PRIVATE_DIRECTORY_MODE).map_err(|_| unavailable())?;
            durable::validate_private_directory(path, "throughput journal directory")
                .map_err(|_| unavailable())?;
        }
        Ok(Self {
            operations,
            active: root.join(THROUGHPUT_ACTIVE_FILENAME),
            lock_path: root.join(THROUGHPUT_LOCK_FILENAME),
            signing,
            profile,
        })
    }

    fn operation_path(&self, operation_id: Uuid) -> PathBuf {
        self.operations.join(format!(
            "{}.json",
            generation_key(&operation_id.to_string())
        ))
    }

    /// `openLock` — creates the lockfile then flock()s it.
    fn open_lock(&self) -> Result<std::os::fd::OwnedFd, Failure> {
        durable::open_lock(&self.lock_path).map_err(|_| unavailable())
    }

    fn validate_record_file(&self, path: &std::path::Path) -> Result<(), Failure> {
        let stat = durable::lstat(path).map_err(|_| unavailable())?;
        durable::validate_private_file(&stat, "throughput journal record")
            .map_err(|_| unavailable())?;
        if stat.st_size <= 0 || stat.st_size as u64 > THROUGHPUT_MAXIMUM_RECORD_BYTES {
            return Err(unavailable());
        }
        Ok(())
    }

    fn write_exclusive_json<T: serde::Serialize>(
        &self,
        path: &std::path::Path,
        value: &T,
    ) -> Result<(), Failure> {
        durable::write_exclusive_json(path, value).map_err(|_| unavailable())
    }

    fn replace_json<T: serde::Serialize>(
        &self,
        path: &std::path::Path,
        value: &T,
    ) -> Result<(), Failure> {
        durable::replace_json(path, value).map_err(|_| unavailable())
    }

    fn operation_payload(record: &ThroughputOperationRecord) -> Result<Vec<u8>, Failure> {
        let mut r = record.clone();
        r.hmac.clear();
        serde_json::to_vec(&r).map_err(|_| unavailable())
    }

    /// `signOperation`.
    fn sign_operation(&self, record: &mut ThroughputOperationRecord) -> Result<(), Failure> {
        let payload = Self::operation_payload(record)?;
        record.hmac = self
            .signing
            .fingerprint(THROUGHPUT_OPERATION_HMAC_DOMAIN, &payload);
        Ok(())
    }

    fn active_payload(record: &ThroughputActiveRecord) -> Result<Vec<u8>, Failure> {
        let mut r = record.clone();
        r.hmac.clear();
        serde_json::to_vec(&r).map_err(|_| unavailable())
    }

    /// `readOperation` — decode + HMAC + full shape validation.
    fn read_operation(&self, operation_id: Uuid) -> Result<ThroughputOperationRecord, Failure> {
        let path = self.operation_path(operation_id);
        if operation_id.is_nil() || self.validate_record_file(&path).is_err() {
            return Err(unavailable());
        }
        let record: ThroughputOperationRecord =
            read_private_json(&path).map_err(|_| unavailable())?;
        if record.operation_id != operation_id {
            return Err(unavailable());
        }
        let payload = Self::operation_payload(&record)?;
        let expected = self
            .signing
            .fingerprint(THROUGHPUT_OPERATION_HMAC_DOMAIN, &payload);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes())
            || self.validate_operation_record(&record).is_err()
        {
            return Err(unavailable());
        }
        Ok(record)
    }

    /// `validateOperationRecord`.
    fn validate_operation_record(&self, record: &ThroughputOperationRecord) -> Result<(), Failure> {
        if record.schema_version != THROUGHPUT_OPERATION_SCHEMA
            || record.operation_id.is_nil()
            || !is_v7(record.operation_id)
            || record.revision == 0
            || wire::is_go_zero_time(record.accepted_at)
            || record.accepted_at >= record.deadline
            || record.deadline > record.accepted_at + MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || record.updated_at < record.accepted_at
        {
            return Err(unavailable());
        }
        match record.phase.as_str() {
            p if p == THROUGHPUT_PHASE_ACCEPTED => {
                if record.revision != 1
                    || !wire::is_go_zero_time(record.measurement_staged_at)
                    || !wire::is_go_zero_time(record.activated_at)
                    || record.updated_at != record.accepted_at
                    || record.evidence.is_some()
                    || record.cleanup.is_some()
                    || record.resolution.is_some()
                {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_MEASUREMENT_PENDING => {
                let Some(evidence) = record.evidence.as_ref() else {
                    return Err(unavailable());
                };
                if record.revision != 2
                    || wire::is_go_zero_time(record.measurement_staged_at)
                    || !wire::is_go_zero_time(record.activated_at)
                    || record.updated_at != record.measurement_staged_at
                    || record.cleanup.is_some()
                    || record.resolution.is_some()
                    || validate_pending_throughput_evidence(
                        &evidence_from_wire(evidence),
                        record.operation_id,
                        record.accepted_at,
                        record.deadline,
                        record.measurement_staged_at,
                        &self.profile,
                    )
                    .is_err()
                {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_COMPLETION_PENDING => {
                if record.revision != 3
                    || !wire::is_go_zero_time(record.activated_at)
                    || record.resolution.is_some()
                    || validate_completion_pending_record(record, &self.profile).is_err()
                {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_COMPLETED => {
                let Some(evidence) = record.evidence.as_ref() else {
                    return Err(unavailable());
                };
                if record.revision != 4
                    || wire::is_go_zero_time(record.activated_at)
                    || record.resolution.is_some()
                    || record.updated_at != record.activated_at
                    || validate_completion_pending_record(record, &self.profile).is_err()
                    || evidence_from_wire(evidence)
                        .valid_at(record.activated_at, &self.profile)
                        .is_err()
                {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_CLEANUP_REQUIRED => {
                if record.resolution.is_some() {
                    return Err(unavailable());
                }
                let from_pending_completion =
                    record.revision == 4 && record.cleanup.is_some() && record.evidence.is_some();
                if from_pending_completion {
                    let cleanup = record.cleanup.as_ref().ok_or_else(unavailable)?;
                    if !wire::is_go_zero_time(record.activated_at)
                        || record.updated_at < cleanup.attested_at
                        || validate_completion_pending_record(record, &self.profile).is_err()
                    {
                        return Err(unavailable());
                    }
                } else {
                    let evidence_ok = match record.evidence.as_ref() {
                        None => record.revision == 2,
                        Some(ev) => {
                            record.revision == 3
                                && validate_pending_throughput_evidence(
                                    &evidence_from_wire(ev),
                                    record.operation_id,
                                    record.accepted_at,
                                    record.deadline,
                                    record.measurement_staged_at,
                                    &self.profile,
                                )
                                .is_ok()
                        }
                    };
                    if record.cleanup.is_some()
                        || !wire::is_go_zero_time(record.activated_at)
                        || !evidence_ok
                        || record.evidence.is_some()
                            != !wire::is_go_zero_time(record.measurement_staged_at)
                        || (!wire::is_go_zero_time(record.measurement_staged_at)
                            && record.updated_at < record.measurement_staged_at)
                    {
                        return Err(unavailable());
                    }
                }
            }
            p if p == THROUGHPUT_PHASE_FAILED => {
                let Some(resolution) = record.resolution.as_ref() else {
                    return Err(unavailable());
                };
                if validate_throughput_cleanup_resolution(resolution, record.operation_id).is_err()
                    || record.updated_at != resolution.resolved_at
                {
                    return Err(unavailable());
                }
                let completed_shape = record.cleanup.is_some() && record.evidence.is_some();
                if completed_shape {
                    if record.revision != 5
                        || !wire::is_go_zero_time(record.activated_at)
                        || validate_completion_pending_record(record, &self.profile).is_err()
                    {
                        return Err(unavailable());
                    }
                } else {
                    let evidence_ok = match record.evidence.as_ref() {
                        None => record.revision == 2 || record.revision == 3,
                        Some(ev) => {
                            (record.revision == 3 || record.revision == 4)
                                && validate_pending_throughput_evidence(
                                    &evidence_from_wire(ev),
                                    record.operation_id,
                                    record.accepted_at,
                                    record.deadline,
                                    record.measurement_staged_at,
                                    &self.profile,
                                )
                                .is_ok()
                        }
                    };
                    if record.cleanup.is_some()
                        || !wire::is_go_zero_time(record.activated_at)
                        || !evidence_ok
                        || record.evidence.is_some()
                            != !wire::is_go_zero_time(record.measurement_staged_at)
                        || (!wire::is_go_zero_time(record.measurement_staged_at)
                            && record.updated_at < record.measurement_staged_at)
                    {
                        return Err(unavailable());
                    }
                }
            }
            _ => return Err(unavailable()),
        }
        Ok(())
    }

    /// `publishActive` — HMAC-signed selector replacement.
    fn publish_active(
        &self,
        operation: &ThroughputOperationRecord,
        receipt_digest: &str,
    ) -> Result<(), Failure> {
        let mut record = ThroughputActiveRecord {
            schema_version: THROUGHPUT_ACTIVE_SCHEMA.to_string(),
            operation_id: operation.operation_id,
            phase: operation.phase.clone(),
            revision: operation.revision,
            updated_at: operation.updated_at,
            receipt_digest: receipt_digest.to_string(),
            hmac: String::new(),
        };
        let payload = Self::active_payload(&record)?;
        record.hmac = self
            .signing
            .fingerprint(THROUGHPUT_ACTIVE_HMAC_DOMAIN, &payload);
        self.replace_json(&self.active, &record)
    }

    /// `readActiveRecord` — decode + validate + HMAC on the selector.
    fn read_active_record(&self) -> Result<(ThroughputActiveRecord, bool), Failure> {
        if durable::lstat(&self.active).is_err() {
            return Ok((ThroughputActiveRecord::default(), false));
        }
        self.validate_record_file(&self.active)?;
        let record: ThroughputActiveRecord =
            read_private_json(&self.active).map_err(|_| unavailable())?;
        if record.schema_version != THROUGHPUT_ACTIVE_SCHEMA
            || record.operation_id.is_nil()
            || !is_v7(record.operation_id)
            || record.revision == 0
            || wire::is_go_zero_time(record.updated_at)
        {
            return Err(unavailable());
        }
        let digest_ok = |r: &ThroughputActiveRecord| r.receipt_digest.is_empty();
        match record.phase.as_str() {
            p if p == THROUGHPUT_PHASE_ACCEPTED => {
                if record.revision != 1 || !digest_ok(&record) {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_MEASUREMENT_PENDING => {
                if record.revision != 2 || !digest_ok(&record) {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_COMPLETION_PENDING => {
                if record.revision != 3 || !digest_ok(&record) {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_CLEANUP_REQUIRED => {
                if !(record.revision == 2 || record.revision == 3 || record.revision == 4)
                    || !digest_ok(&record)
                {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_FAILED => {
                if !(2..=5).contains(&record.revision) || !digest_ok(&record) {
                    return Err(unavailable());
                }
            }
            p if p == THROUGHPUT_PHASE_COMPLETED => {
                if record.revision != 4 || !wire::valid_prefixed_sha256(&record.receipt_digest) {
                    return Err(unavailable());
                }
            }
            _ => return Err(unavailable()),
        }
        let payload = Self::active_payload(&record)?;
        let expected = self
            .signing
            .fingerprint(THROUGHPUT_ACTIVE_HMAC_DOMAIN, &payload);
        if !wire::hmac_equal(record.hmac.as_bytes(), expected.as_bytes()) {
            return Err(unavailable());
        }
        Ok((record, true))
    }

    /// `readCoherentOperation` — the operation record must match the
    /// selector exactly (and, when completed, the receipt digest).
    fn read_coherent_operation(
        &self,
        active: &ThroughputActiveRecord,
    ) -> Result<ThroughputOperationRecord, Failure> {
        let record = self.read_operation(active.operation_id)?;
        if record.phase != active.phase
            || record.revision != active.revision
            || record.updated_at != active.updated_at
        {
            return Err(unavailable());
        }
        if active.phase == THROUGHPUT_PHASE_COMPLETED {
            let Some(evidence) = record.evidence.as_ref() else {
                return Err(unavailable());
            };
            let digest = throughput_evidence_digest(&evidence_from_wire(evidence))?;
            if digest != active.receipt_digest {
                return Err(unavailable());
            }
        }
        Ok(record)
    }

    /// `Accept` — stage a new attempt; idempotent for the identical
    /// live operation, fenced while any non-terminal operation lives.
    pub fn accept(
        &self,
        operation_id: Uuid,
        accepted_at: OffsetDateTime,
        deadline: OffsetDateTime,
    ) -> Result<(), Failure> {
        let accepted_at = accepted_at.to_offset(time::UtcOffset::UTC);
        let deadline = deadline.to_offset(time::UtcOffset::UTC);
        if operation_id.is_nil()
            || !is_v7(operation_id)
            || wire::is_go_zero_time(accepted_at)
            || accepted_at >= deadline
            || deadline > accepted_at + MAXIMUM_THROUGHPUT_PROBE_ELAPSED
        {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(), Failure> {
            let (active, found) = self.read_active_record()?;
            if found && active.operation_id == operation_id {
                let stored = self.read_operation(operation_id)?;
                if stored.accepted_at != accepted_at || stored.deadline != deadline {
                    return Err(unavailable());
                }
                return Ok(());
            }
            if found
                && (active.phase == THROUGHPUT_PHASE_ACCEPTED
                    || active.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    || active.phase == THROUGHPUT_PHASE_COMPLETION_PENDING
                    || active.phase == THROUGHPUT_PHASE_CLEANUP_REQUIRED)
            {
                return Err(unavailable());
            }
            if found {
                self.read_coherent_operation(&active)?;
            }
            let mut record = ThroughputOperationRecord {
                schema_version: THROUGHPUT_OPERATION_SCHEMA.to_string(),
                operation_id,
                phase: THROUGHPUT_PHASE_ACCEPTED.to_string(),
                revision: 1,
                accepted_at,
                deadline,
                updated_at: accepted_at,
                ..ThroughputOperationRecord::default()
            };
            self.sign_operation(&mut record)?;
            let path = self.operation_path(operation_id);
            if self.write_exclusive_json(&path, &record).is_err() {
                let stored = self.read_operation(operation_id)?;
                if !same_throughput_operation(&stored, &record) {
                    return Err(unavailable());
                }
            }
            self.publish_active(&record, "")
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `AcceptedContext` — the live acceptance window for the
    /// operation.
    pub fn accepted_context(
        &self,
        operation_id: Uuid,
    ) -> Result<(OffsetDateTime, OffsetDateTime), Failure> {
        if operation_id.is_nil() {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(OffsetDateTime, OffsetDateTime), Failure> {
            let (active, found) = self.read_active_record()?;
            if !found
                || active.operation_id != operation_id
                || (active.phase != THROUGHPUT_PHASE_ACCEPTED
                    && active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING)
            {
                return Err(unavailable());
            }
            let record = self.read_coherent_operation(&active)?;
            Ok((record.accepted_at, record.deadline))
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `PendingMeasurement` — the staged evidence awaiting the
    /// cleanup attestation.
    pub fn pending_measurement(
        &self,
        operation_id: Uuid,
    ) -> Result<(ThroughputEvidence, OffsetDateTime), Failure> {
        if operation_id.is_nil() {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(ThroughputEvidence, OffsetDateTime), Failure> {
            let (active, found) = self.read_active_record()?;
            if !found
                || active.operation_id != operation_id
                || active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
            {
                return Err(unavailable());
            }
            let record = self.read_coherent_operation(&active)?;
            let Some(evidence) = record.evidence.as_ref() else {
                return Err(unavailable());
            };
            if wire::is_go_zero_time(record.measurement_staged_at) {
                return Err(unavailable());
            }
            Ok((evidence_from_wire(evidence), record.measurement_staged_at))
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `CurrentAttempt` — the selector's view of the live attempt,
    /// including the crash cut point where the selector trails the
    /// operation record by exactly one committed transition.
    pub fn current_attempt(&self) -> Result<(ThroughputOperationRecord, bool), Failure> {
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(ThroughputOperationRecord, bool), Failure> {
            let (active, found) = self.read_active_record()?;
            if !found {
                return Ok((ThroughputOperationRecord::default(), false));
            }
            let mut record = self.read_operation(active.operation_id)?;
            if record.phase == active.phase
                && record.revision == active.revision
                && record.updated_at == active.updated_at
            {
                record.selector_phase = active.phase;
                return Ok((record, true));
            }
            let transition_cutpoint = (active.phase == THROUGHPUT_PHASE_ACCEPTED
                && active.revision == 1
                && record.revision == 2
                && (record.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    || record.phase == THROUGHPUT_PHASE_FAILED
                    || record.phase == THROUGHPUT_PHASE_CLEANUP_REQUIRED))
                || (active.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    && active.revision == 2
                    && record.revision == 3
                    && (record.phase == THROUGHPUT_PHASE_COMPLETION_PENDING
                        || record.phase == THROUGHPUT_PHASE_FAILED
                        || record.phase == THROUGHPUT_PHASE_CLEANUP_REQUIRED))
                || (active.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    && active.revision == 2
                    && record.revision == 4
                    && record.phase == THROUGHPUT_PHASE_CLEANUP_REQUIRED)
                || (active.phase == THROUGHPUT_PHASE_COMPLETION_PENDING
                    && active.revision == 3
                    && record.revision == 4
                    && (record.phase == THROUGHPUT_PHASE_COMPLETED
                        || record.phase == THROUGHPUT_PHASE_CLEANUP_REQUIRED))
                || (active.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    && active.revision == 2
                    && record.revision == 4
                    && record.phase == THROUGHPUT_PHASE_COMPLETED)
                || (active.phase == THROUGHPUT_PHASE_CLEANUP_REQUIRED
                    && record.phase == THROUGHPUT_PHASE_FAILED
                    && record.revision == active.revision + 1);
            if !transition_cutpoint {
                return Err(unavailable());
            }
            record.selector_phase = active.phase;
            Ok((record, true))
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `StageMeasurement` — idempotent staging of the pending
    /// evidence inside the acceptance window.
    pub fn stage_measurement(
        &self,
        operation_id: Uuid,
        evidence: ThroughputEvidence,
        staged_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        let staged_at = staged_at.to_offset(time::UtcOffset::UTC);
        let evidence = normalize_pending_throughput_evidence(evidence);
        if wire::is_go_zero_time(staged_at) {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(), Failure> {
            let (active, found) = self.read_active_record()?;
            if !found
                || active.operation_id != operation_id
                || (active.phase != THROUGHPUT_PHASE_ACCEPTED
                    && active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING)
            {
                return Err(unavailable());
            }
            let mut record = self.read_operation(operation_id)?;
            if validate_pending_throughput_evidence(
                &evidence,
                record.operation_id,
                record.accepted_at,
                record.deadline,
                staged_at,
                &self.profile,
            )
            .is_err()
            {
                return Err(unavailable());
            }
            if record.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING {
                let Some(stored) = record.evidence.as_ref() else {
                    return Err(unavailable());
                };
                if evidence_from_wire(stored) != evidence
                    || record.measurement_staged_at != staged_at
                {
                    return Err(unavailable());
                }
                return self.publish_active(&record, "");
            }
            if record.phase != THROUGHPUT_PHASE_ACCEPTED
                || active.phase != THROUGHPUT_PHASE_ACCEPTED
                || active.revision != record.revision
            {
                return Err(unavailable());
            }
            record.phase = THROUGHPUT_PHASE_MEASUREMENT_PENDING.to_string();
            record.revision += 1;
            record.measurement_staged_at = staged_at;
            record.updated_at = staged_at;
            record.evidence = Some(evidence_to_wire(&evidence));
            self.sign_operation(&mut record)?;
            if self
                .replace_json(&self.operation_path(operation_id), &record)
                .is_err()
            {
                return Err(unavailable());
            }
            self.publish_active(&record, "")
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `CompletePendingCleanupAttested` — moves the staged evidence
    /// into `completion_pending` once the root attestation drains the
    /// probe tree.
    pub fn complete_pending_cleanup_attested(
        &self,
        operation_id: Uuid,
        attestation: ThroughputCleanupAttestation,
        now: OffsetDateTime,
    ) -> Result<(), Failure> {
        let now = now.to_offset(time::UtcOffset::UTC);
        let mut attestation = attestation;
        attestation.attested_at = attestation.attested_at.to_offset(time::UtcOffset::UTC);
        if wire::is_go_zero_time(now) {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(), Failure> {
            let (active, found) = self.read_active_record()?;
            if !found
                || active.operation_id != operation_id
                || (active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    && active.phase != THROUGHPUT_PHASE_COMPLETION_PENDING)
            {
                return Err(unavailable());
            }
            let mut record = self.read_operation(operation_id)?;
            if record.phase == THROUGHPUT_PHASE_COMPLETION_PENDING {
                let Some(cleanup) = record.cleanup.as_ref() else {
                    return Err(unavailable());
                };
                if *cleanup != attestation
                    || record.evidence.is_none()
                    || !wire::is_go_zero_time(record.activated_at)
                    || (active.phase != THROUGHPUT_PHASE_COMPLETION_PENDING
                        && active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING)
                {
                    return Err(unavailable());
                }
                return self.publish_active(&record, "");
            }
            if record.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
                || record.evidence.is_none()
                || active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
                || active.revision != record.revision
                || validate_throughput_cleanup_attestation(&attestation, &record, now).is_err()
            {
                return Err(unavailable());
            }
            let receipt_id = Uuid::now_v7();
            let mut completed =
                evidence_from_wire(record.evidence.as_ref().ok_or_else(unavailable)?);
            completed.receipt_id = receipt_id;
            completed.probe_completed_at = attestation.attested_at;
            completed.probe_elapsed = attestation.parent_elapsed;
            completed.measured_at = attestation.attested_at;
            completed.expires_at = attestation.attested_at + self.profile.throughput_max_age;
            completed.cleanup_state = BACKUP_THROUGHPUT_CLEANUP_CLEAN.to_string();
            completed.cleanup_verified_at = attestation.attested_at;
            if completed.valid_at(now, &self.profile).is_err() {
                return Err(unavailable());
            }
            record.phase = THROUGHPUT_PHASE_COMPLETION_PENDING.to_string();
            record.revision += 1;
            record.updated_at = attestation.attested_at;
            record.evidence = Some(evidence_to_wire(&completed));
            record.cleanup = Some(attestation);
            self.sign_operation(&mut record)?;
            if self
                .replace_json(&self.operation_path(operation_id), &record)
                .is_err()
            {
                return Err(unavailable());
            }
            self.publish_active(&record, "")
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `ActivateCompletion` — publishes the measured receipt:
    /// idempotent inside the validity window, otherwise promotes
    /// `completion_pending` to `completed` and binds the digest into
    /// the selector.
    pub fn activate_completion(
        &self,
        operation_id: Uuid,
        activated_at: OffsetDateTime,
    ) -> Result<ThroughputEvidence, Failure> {
        let activated_at = activated_at.to_offset(time::UtcOffset::UTC);
        if wire::is_go_zero_time(activated_at) {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<ThroughputEvidence, Failure> {
            let (active, found) = self.read_active_record()?;
            if !found
                || active.operation_id != operation_id
                || (active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    && active.phase != THROUGHPUT_PHASE_COMPLETION_PENDING
                    && active.phase != THROUGHPUT_PHASE_COMPLETED)
            {
                return Err(unavailable());
            }
            let mut record = self.read_operation(operation_id)?;
            if record.evidence.is_none() || record.cleanup.is_none() {
                return Err(unavailable());
            }
            if record.phase == THROUGHPUT_PHASE_COMPLETED {
                let evidence =
                    evidence_from_wire(record.evidence.as_ref().ok_or_else(unavailable)?);
                let cleanup = record.cleanup.as_ref().ok_or_else(unavailable)?;
                if activated_at < cleanup.attested_at || activated_at >= evidence.expires_at {
                    return Err(unavailable());
                }
                let digest = throughput_evidence_digest(&evidence)?;
                if evidence.valid_at(activated_at, &self.profile).is_err()
                    || self.publish_active(&record, &digest).is_err()
                {
                    return Err(unavailable());
                }
                return Ok(evidence);
            }
            let pending_selector_coherent = (active.phase == THROUGHPUT_PHASE_COMPLETION_PENDING
                && active.revision == record.revision)
                || (active.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    && active.revision == 2
                    && record.revision == 3);
            let evidence = evidence_from_wire(record.evidence.as_ref().ok_or_else(unavailable)?);
            if record.phase != THROUGHPUT_PHASE_COMPLETION_PENDING
                || !pending_selector_coherent
                || activated_at < record.updated_at
                || activated_at >= evidence.expires_at
                || evidence.valid_at(activated_at, &self.profile).is_err()
            {
                return Err(unavailable());
            }
            record.phase = THROUGHPUT_PHASE_COMPLETED.to_string();
            record.revision += 1;
            record.activated_at = activated_at;
            record.updated_at = activated_at;
            self.sign_operation(&mut record)?;
            if self
                .replace_json(&self.operation_path(operation_id), &record)
                .is_err()
            {
                return Err(unavailable());
            }
            let digest = throughput_evidence_digest(&evidence)?;
            self.publish_active(&record, &digest)?;
            Ok(evidence)
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `MarkFailed` — terminal failure with a zero-count resolution.
    pub fn mark_failed(
        &self,
        operation_id: Uuid,
        failed_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        let resolution = new_throughput_cleanup_resolution(
            operation_id,
            ThroughputCleanupCounts::default(),
            failed_at,
        )?;
        self.mark_failed_cleanup_attested(operation_id, resolution)
    }

    /// `MarkCleanupRequired` — terminal phase that demands a later
    /// cleanup resolution.
    pub fn mark_cleanup_required(
        &self,
        operation_id: Uuid,
        failed_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        self.mark_terminal(operation_id, THROUGHPUT_PHASE_CLEANUP_REQUIRED, failed_at)
    }

    /// `MarkFailedCleanupAttested`.
    pub fn mark_failed_cleanup_attested(
        &self,
        operation_id: Uuid,
        resolution: ThroughputCleanupResolution,
    ) -> Result<(), Failure> {
        self.resolve_clean(operation_id, resolution, false)
    }

    /// `ResolveCleanupRequired`.
    pub fn resolve_cleanup_required(
        &self,
        operation_id: Uuid,
        resolution: ThroughputCleanupResolution,
    ) -> Result<(), Failure> {
        self.resolve_clean(operation_id, resolution, true)
    }

    /// `resolveClean`.
    fn resolve_clean(
        &self,
        operation_id: Uuid,
        resolution: ThroughputCleanupResolution,
        require_cleanup_required: bool,
    ) -> Result<(), Failure> {
        let mut resolution = resolution;
        resolution.resolved_at = resolution.resolved_at.to_offset(time::UtcOffset::UTC);
        if operation_id.is_nil()
            || validate_throughput_cleanup_resolution(&resolution, operation_id).is_err()
        {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(), Failure> {
            let (active, found) = self.read_active_record()?;
            if !found || active.operation_id != operation_id {
                return Err(unavailable());
            }
            let mut record = self.read_operation(operation_id)?;
            if record.phase == THROUGHPUT_PHASE_FAILED {
                let Some(stored) = record.resolution.as_ref() else {
                    return Err(unavailable());
                };
                if *stored != resolution
                    || (active.phase != THROUGHPUT_PHASE_FAILED
                        && active.phase != THROUGHPUT_PHASE_ACCEPTED
                        && active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
                        && active.phase != THROUGHPUT_PHASE_CLEANUP_REQUIRED)
                {
                    return Err(unavailable());
                }
                return self.publish_active(&record, "");
            }
            if require_cleanup_required {
                if record.phase != THROUGHPUT_PHASE_CLEANUP_REQUIRED {
                    return Err(unavailable());
                }
            } else if record.phase != THROUGHPUT_PHASE_ACCEPTED
                && record.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
            {
                return Err(unavailable());
            }
            let mut coherent = active.phase == record.phase && active.revision == record.revision;
            if require_cleanup_required
                && !coherent
                && interrupted_cleanup_required_publish(&active, &record)
            {
                self.publish_active(&record, "")?;
                coherent = true;
            }
            if !coherent || resolution.resolved_at < record.updated_at {
                return Err(unavailable());
            }
            record.phase = THROUGHPUT_PHASE_FAILED.to_string();
            record.revision += 1;
            record.updated_at = resolution.resolved_at;
            record.resolution = Some(resolution);
            self.sign_operation(&mut record)?;
            if self
                .replace_json(&self.operation_path(operation_id), &record)
                .is_err()
            {
                return Err(unavailable());
            }
            self.publish_active(&record, "")
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `markTerminal`.
    fn mark_terminal(
        &self,
        operation_id: Uuid,
        phase: &str,
        failed_at: OffsetDateTime,
    ) -> Result<(), Failure> {
        let failed_at = failed_at.to_offset(time::UtcOffset::UTC);
        if operation_id.is_nil()
            || (phase != THROUGHPUT_PHASE_FAILED && phase != THROUGHPUT_PHASE_CLEANUP_REQUIRED)
            || wire::is_go_zero_time(failed_at)
        {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = (|| -> Result<(), Failure> {
            let (active, found) = self.read_active_record()?;
            if !found || active.operation_id != operation_id {
                return Err(unavailable());
            }
            let mut record = self.read_operation(operation_id)?;
            if record.phase == phase {
                if active.phase != phase
                    && active.phase != THROUGHPUT_PHASE_ACCEPTED
                    && active.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
                    && active.phase != THROUGHPUT_PHASE_COMPLETION_PENDING
                {
                    return Err(unavailable());
                }
                return self.publish_active(&record, "");
            }
            let from_completion_pending = record.phase == THROUGHPUT_PHASE_COMPLETION_PENDING
                && phase == THROUGHPUT_PHASE_CLEANUP_REQUIRED;
            let coherent_current =
                active.phase == record.phase && active.revision == record.revision;
            let interrupted_pending_publish = from_completion_pending
                && active.phase == THROUGHPUT_PHASE_MEASUREMENT_PENDING
                && active.revision == 2;
            if (record.phase != THROUGHPUT_PHASE_ACCEPTED
                && record.phase != THROUGHPUT_PHASE_MEASUREMENT_PENDING
                && !from_completion_pending)
                || (!coherent_current && !interrupted_pending_publish)
                || failed_at < record.updated_at
            {
                return Err(unavailable());
            }
            record.phase = phase.to_string();
            record.revision += 1;
            record.updated_at = failed_at;
            self.sign_operation(&mut record)?;
            if self
                .replace_json(&self.operation_path(operation_id), &record)
                .is_err()
            {
                return Err(unavailable());
            }
            self.publish_active(&record, "")
        })();
        durable::unlock_and_close(lock);
        outcome
    }

    /// `ReadActive` — the live receipt if and only if the selector
    /// and operation record agree on a completed attempt.
    pub fn read_active(&self, now: OffsetDateTime) -> Result<ThroughputEvidence, Failure> {
        if wire::is_go_zero_time(now) {
            return Err(unavailable());
        }
        let lock = self.open_lock()?;
        let outcome = self.read_active_evidence(now.to_offset(time::UtcOffset::UTC));
        durable::unlock_and_close(lock);
        outcome
    }

    /// `ReadActiveForBinding`.
    pub fn read_active_for_binding(
        &self,
        now: OffsetDateTime,
        binding: &central_backup::recovery::profile::ThroughputEvidenceBinding,
    ) -> Result<ThroughputEvidence, Failure> {
        let evidence = self.read_active(now)?;
        if evidence
            .valid_for(now.to_offset(time::UtcOffset::UTC), &self.profile, binding)
            .is_err()
        {
            return Err(unavailable());
        }
        Ok(evidence)
    }

    /// `readActiveEvidence`.
    fn read_active_evidence(&self, now: OffsetDateTime) -> Result<ThroughputEvidence, Failure> {
        let (active, found) = self.read_active_record()?;
        if !found
            || active.phase != THROUGHPUT_PHASE_COMPLETED
            || !wire::valid_prefixed_sha256(&active.receipt_digest)
        {
            return Err(unavailable());
        }
        let record = self.read_coherent_operation(&active)?;
        let Some(evidence) = record.evidence.as_ref() else {
            return Err(unavailable());
        };
        if record.cleanup.is_none() {
            return Err(unavailable());
        }
        let evidence = evidence_from_wire(evidence);
        if evidence.valid_at(now, &self.profile).is_err() {
            return Err(unavailable());
        }
        let digest = throughput_evidence_digest(&evidence)?;
        if digest != active.receipt_digest {
            return Err(unavailable());
        }
        Ok(evidence)
    }
}
