//! `restore_admission.go` — the C03 admission judge. It closes restore
//! admission over immutable repository evidence, the protected broker
//! seal, the current destination binding, and a fresh per-device
//! capacity plan. It owns no mutation capability, accepts no CLI
//! values, and returns only locator-free ticket facts: every quantity
//! that reaches the ticket is re-derived from sealed manifest content
//! the inspector verified itself, never copied off the caller's flat
//! evidence fields.

#![forbid(unsafe_code)]

use central_backup::backup::capacity::{RecoveryProfile, restore_admission_margin};
use central_backup::backup::inventory::MAXIMUM_INVENTORY_CHUNK_ENTRIES;
use central_backup::backup::operation::{
    BACKUP_DATABASE_SCHEMA_VERSION, BACKUP_DUMP_TOOL_VERSION, BackupAcceptedFacts,
};
use central_backup::domain::TargetIdentity;
use central_backup::port::{
    BackupSealVerifier, RecoveryVerificationEvidence, RestoreAdmissionFacts,
};
use central_backup::recovery::refusal::RestoreRefusalReason;
use central_foundation::failure::Failure;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use super::repository::Repository;

/// `restoreAdmissionToolVersion` — the pinned `pg_restore` admission
/// binds; a live target reporting anything else is refused.
pub const RESTORE_ADMISSION_TOOL_VERSION: &str = "pg_restore-16.14";

/// `restoreCapacityEvidenceSchema` — the canonical evidence schema the
/// ticket's capacity digest binds.
pub const RESTORE_CAPACITY_EVIDENCE_SCHEMA: &str = "central.restore-capacity-evidence/v1";

/// `maximumRestoreAdmissionDevices`.
pub const MAXIMUM_RESTORE_ADMISSION_DEVICES: usize = 8;

/// `ErrRestoreAdmission` — intentionally safe for logs and operator
/// results. A backing adapter's database, repository, device, or
/// protected-state error is never propagated because it may contain a
/// locator or implementation detail.
pub(crate) fn restore_admission_unavailable() -> Failure {
    Failure::unavailable("restore_admission", "restore admission is unavailable")
}

/// `RestoreTargetAdmission` — the locator-free current target
/// observation used to compare a sealed backup with the destination.
/// Its implementation must derive these values from protected payload
/// authority, installed immutable configuration, and a read-only
/// target session rather than CLI input.
#[derive(Debug, Clone)]
pub struct RestoreTargetAdmission {
    /// Destination target identity.
    pub target: TargetIdentity,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// Security epoch.
    pub security_epoch: u64,
    /// Restore epoch.
    pub restore_epoch: u64,
    /// `sha256:`-prefixed config fingerprint.
    pub config_fingerprint: String,
    /// Payload epoch identity (v7).
    pub payload_epoch_id: Uuid,
    /// Pinned schema version.
    pub database_schema_version: String,
    /// Pinned restore tool version.
    pub restore_tool_version: String,
}

/// `RestoreTargetAdmissionSource` — the trusted current-target
/// authority.
pub trait RestoreTargetAdmissionSource: Send + Sync {
    /// `ReadRestoreTargetAdmission`.
    fn read_restore_target_admission(
        &self,
        backup_id: Uuid,
    ) -> Result<RestoreTargetAdmission, Failure>;
}

/// `RestoreCapacityRequest` — only bounded, sealed-media quantities
/// and opaque identities. It gives a trusted capacity planner enough
/// information to include PostgreSQL/WAL/temp/object demand without
/// exposing a repository path, object key, mount point, or credential.
#[derive(Debug, Clone, Copy)]
pub struct RestoreCapacityRequest {
    /// Sealed backup identity.
    pub backup_id: Uuid,
    /// Repository binding identity.
    pub repository_binding_id: Uuid,
    /// Sealed dump bytes.
    pub dump_bytes: u64,
    /// Sealed object bytes.
    pub object_bytes: u64,
    /// Sealed artifact count.
    pub artifact_count: u64,
}

/// `RestoreDeviceCapacity` — one mount-identity-derived observation.
/// `planned_bytes` is the trusted source's canonical incremental
/// demand for this device before the admission margin;
/// `available_bytes` comes from a fresh descriptor-relative filesystem
/// observation and already excludes allocated reserve blocks.
#[derive(Debug, Clone)]
pub struct RestoreDeviceCapacity {
    /// `sha256:`-prefixed opaque mount identity.
    pub device_id: String,
    /// Free bytes observed at measurement.
    pub available_bytes: u64,
    /// Canonical planned incremental demand.
    pub planned_bytes: u64,
    /// `sha256:`-prefixed digest of the reserve receipts.
    pub reserve_evidence_digest: String,
    /// The reserve proof verified.
    pub reserve_verified: bool,
}

/// `RestoreCapacityAdmission` — the trusted planner's fresh,
/// locator-free capacity answer.
#[derive(Debug, Clone)]
pub struct RestoreCapacityAdmission {
    /// Observation instant, stamped by the source itself.
    pub observed_at: time::OffsetDateTime,
    /// Per-device capacities (sorted by `device_id`).
    pub devices: Vec<RestoreDeviceCapacity>,
}

/// `RestoreCapacitySource` — the trusted per-device capacity planner.
pub trait RestoreCapacitySource: Send + Sync {
    /// `ReadRestoreCapacity`.
    fn read_restore_capacity(
        &self,
        request: RestoreCapacityRequest,
    ) -> Result<RestoreCapacityAdmission, Failure>;
}

/// The adapter-side `RestoreAdmissionInspector`: judges the
/// destination against evidence that has already been verified once,
/// bound to its own read-only [`Repository`]. (Named for the
/// repository it guards; the capability trait it implements is
/// `central_backup::port::RestoreAdmissionInspector`.)
pub struct RepositoryAdmissionInspector {
    repository: Repository,
    seals: Arc<dyn BackupSealVerifier>,
    target: Arc<dyn RestoreTargetAdmissionSource>,
    capacity: Box<dyn RestoreCapacitySource>,
    profile: RecoveryProfile,
}

/// `NewRestoreAdmissionInspector` — refuses unless the repository is a
/// validated read-only handle, every authority is present, and the
/// installed recovery profile validates. `target` is shared (`Arc`)
/// because upstream's `productionRestoreAdmissionInspector` passes the
/// same trusted reader into the inspector it builds on every call.
pub fn new_repository_admission_inspector(
    repository: Repository,
    seals: Arc<dyn BackupSealVerifier>,
    target: Arc<dyn RestoreTargetAdmissionSource>,
    capacity: Box<dyn RestoreCapacitySource>,
    profile: RecoveryProfile,
) -> Result<RepositoryAdmissionInspector, Failure> {
    if !repository.is_read_only() || repository.validate().is_err() || profile.validate().is_err() {
        return Err(restore_admission_unavailable());
    }
    Ok(RepositoryAdmissionInspector {
        repository,
        seals,
        target,
        capacity,
        profile,
    })
}

/// `restoreSealedMedia` — what the inspector established for itself
/// about the evidence it was handed. Nothing outside
/// [`RepositoryAdmissionInspector::assert_sealed_media`] may populate
/// it, and inspection uses only these values — never the caller's
/// corresponding flat fields — so a field that escaped the assertions
/// cannot reach the target comparison or the capacity request.
struct RestoreSealedMedia {
    accepted_facts: BackupAcceptedFacts,
    dump: central_backup::backup::operation::DumpEvidence,
    artifact_count: u64,
    object_bytes: u64,
}

impl RepositoryAdmissionInspector {
    /// `assertSealedMedia` — asserts the seal chain directly over the
    /// single verification walk the caller already performed, against
    /// two authorities the caller does not supply:
    ///
    /// - `self.repository`'s own validated descriptor, which the
    ///   evidence's repository binding must name; and
    /// - `self.seals`, the broker's protected seal record, which must
    ///   attest the exact digests carried here.
    ///
    /// Everything the admission decision consumes — the accepted
    /// facts, the dump size, the artifact count, the object bytes — is
    /// re-derived from the verified manifest rather than read off the
    /// caller's flat fields, so a fabricated or edited evidence value
    /// cannot size a reserve or match a target.
    fn assert_sealed_media(
        &self,
        backup_id: Uuid,
        evidence: &RecoveryVerificationEvidence,
    ) -> Result<RestoreSealedMedia, Failure> {
        if !self.repository.is_read_only() || self.profile.validate().is_err() {
            return Err(restore_admission_unavailable());
        }
        let manifest = &evidence.manifest;
        let (artifact_count, object_bytes) = sealed_manifest_totals(manifest, &self.profile)?;
        if evidence.backup_id != backup_id
            || manifest.backup_id != backup_id
            || evidence.repository_binding_id != self.repository.binding_id()
            || manifest.repository_binding_id != evidence.repository_binding_id
            || manifest.operation_id != evidence.operation_id
            || manifest.verify().is_err()
            || manifest.digest != evidence.manifest_digest
            || manifest.dump != evidence.dump
            || artifact_count != evidence.artifact_count
            || object_bytes != evidence.object_bytes
        {
            return Err(restore_admission_unavailable());
        }
        self.seals
            .verify_backup_seal(
                backup_id,
                evidence.manifest_digest,
                evidence.seal_companion_digest,
                evidence.file_tree_digest,
                evidence.repository_manifest_digest,
                evidence.repository_revision,
            )
            .map_err(|_| restore_admission_unavailable())?;
        Ok(RestoreSealedMedia {
            accepted_facts: manifest.accepted_facts.clone(),
            dump: manifest.dump,
            artifact_count,
            object_bytes,
        })
    }
}

impl central_backup::port::RestoreAdmissionInspector for RepositoryAdmissionInspector {
    /// `InspectRestoreAdmission` — the seal chain, then the live
    /// target admission, then a fresh per-device capacity plan under
    /// the 1.25× margin.
    fn inspect_restore_admission(
        &self,
        backup_id: Uuid,
        evidence: &RecoveryVerificationEvidence,
    ) -> Result<RestoreAdmissionFacts, Failure> {
        if backup_id.is_nil()
            || backup_id.get_version_num() != 7
            || self.profile.validate().is_err()
        {
            return Err(restore_admission_unavailable());
        }
        let sealed = self.assert_sealed_media(backup_id, evidence)?;
        let target = self
            .target
            .read_restore_target_admission(backup_id)
            .map_err(|_| restore_admission_unavailable())?;
        if validate_restore_target_admission(&target, &sealed.accepted_facts).is_err() {
            // Distinct from the unavailable sentinel: this is "stale",
            // not "unavailable". The dominant real cause is a target
            // whose restore/security epochs have advanced (any
            // successful restore apply does this as part of the C05
            // authority reset) since this backup was sealed —
            // permanently, not transiently, invalid for this backup.
            // See `RestoreRefusalReason::TargetAdmissionStale`.
            return Err(RestoreRefusalReason::TargetAdmissionStale.into_failure());
        }

        // Every quantity below is the value this inspector re-derived
        // from broker-sealed manifest content, not the flat field it
        // was handed.
        let request = RestoreCapacityRequest {
            backup_id,
            repository_binding_id: self.repository.binding_id(),
            dump_bytes: sealed.dump.size as u64,
            object_bytes: sealed.object_bytes,
            artifact_count: sealed.artifact_count,
        };
        let capacity_started_at = time::OffsetDateTime::now_utc();
        let capacity = self
            .capacity
            .read_restore_capacity(request)
            .map_err(|_| restore_admission_unavailable())?;
        let capacity_completed_at = time::OffsetDateTime::now_utc();
        if validate_restore_capacity(
            &capacity,
            &request,
            capacity_started_at,
            capacity_completed_at,
        )
        .is_err()
        {
            return Err(restore_admission_unavailable());
        }
        let capacity_evidence_digest = restore_capacity_evidence_digest(&request, &capacity)
            .map_err(|_| restore_admission_unavailable())?;
        Ok(RestoreAdmissionFacts {
            target: target.target,
            target_fingerprint: target.target_fingerprint,
            security_epoch: target.security_epoch,
            restore_epoch: target.restore_epoch,
            config_fingerprint: target.config_fingerprint,
            payload_epoch_id: target.payload_epoch_id,
            database_schema_version: target.database_schema_version,
            capacity_evidence_digest,
            tool_version: target.restore_tool_version,
        })
    }
}

/// `sealedManifestTotals` — re-sums the artifact count and object
/// bytes from the sealed inventory entries and re-applies this
/// inspector's own profile caps to them. The same accounting the
/// media walk performs, done again over content the manifest digest
/// covers — an independent recomputation rather than a copy of the
/// caller's counters, so a narrower installed profile still refuses
/// evidence a wider one produced.
fn sealed_manifest_totals(
    manifest: &central_backup::backup::manifest::SealRootManifest,
    profile: &RecoveryProfile,
) -> Result<(u64, u64), Failure> {
    let maximum_chunks = profile
        .max_record_count
        .div_ceil(MAXIMUM_INVENTORY_CHUNK_ENTRIES as u64);
    if manifest.chunks.len() as u64 > maximum_chunks {
        return Err(restore_admission_unavailable());
    }
    let (mut artifact_count, mut object_bytes) = (0u64, 0u64);
    for chunk in &manifest.chunks {
        for entry in &chunk.entries {
            if entry.size < 0
                || artifact_count >= profile.max_record_count
                || entry.size as u64 > profile.max_object_bytes - object_bytes
            {
                return Err(restore_admission_unavailable());
            }
            artifact_count += 1;
            object_bytes += entry.size as u64;
        }
    }
    Ok((artifact_count, object_bytes))
}

/// `validateRestoreTargetAdmission` — the live target observation
/// must agree with the sealed accepted facts on every dimension that
/// binds this backup: identity, fingerprints, payload epoch, schema,
/// and pinned tool versions.
fn validate_restore_target_admission(
    current: &RestoreTargetAdmission,
    sealed: &BackupAcceptedFacts,
) -> Result<(), Failure> {
    if sealed.validate().is_err()
        || !current.target.is_valid()
        || current.target.database != "central"
        || current.target.epoch != current.restore_epoch
        || current.restore_epoch == u64::MAX
        || current.security_epoch == u64::MAX
        || !valid_restore_admission_fingerprint(&current.target_fingerprint)
        || current.target_fingerprint != sealed.target_fingerprint
        || !valid_restore_admission_fingerprint(&current.config_fingerprint)
        || current.config_fingerprint != sealed.config_fingerprint
        || current.target.config_hash != current.config_fingerprint
        || current.payload_epoch_id.is_nil()
        || current.payload_epoch_id.get_version_num() != 7
        || current.target_fingerprint
            != restore_admission_target_fingerprint(&current.target, current.payload_epoch_id)
        || current.payload_epoch_id != sealed.payload_epoch_id
        || current.database_schema_version != BACKUP_DATABASE_SCHEMA_VERSION
        || current.database_schema_version != sealed.database_schema_version
        || sealed.tool_version != BACKUP_DUMP_TOOL_VERSION
        || current.restore_tool_version != RESTORE_ADMISSION_TOOL_VERSION
    {
        return Err(restore_admission_unavailable());
    }
    Ok(())
}

/// `restoreAdmissionTargetFingerprint` — the SHA-256 binding of the
/// target identity and payload epoch admission recomputes.
#[must_use]
pub fn restore_admission_target_fingerprint(
    target: &TargetIdentity,
    payload_epoch_id: Uuid,
) -> String {
    let digest = Sha256::digest(
        format!(
            "central.backup-target/v1\x00{}\x00{}\x00{}\x00{}\x00{}\x00{}",
            target.system_id,
            target.database_oid,
            target.database,
            target.config_hash,
            target.epoch,
            payload_epoch_id
        )
        .as_bytes(),
    );
    format!("sha256:{}", crate::broker::wire::hex_encode(&digest))
}

/// `validateRestoreCapacity` — a fresh, in-window, per-device
/// observation whose planned total covers the sealed bytes and whose
/// available total covers planned under the 1.25× margin.
fn validate_restore_capacity(
    capacity: &RestoreCapacityAdmission,
    request: &RestoreCapacityRequest,
    started_at: time::OffsetDateTime,
    completed_at: time::OffsetDateTime,
) -> Result<(), Failure> {
    if request.backup_id.is_nil()
        || request.repository_binding_id.is_nil()
        || request.dump_bytes == 0
        || super::environment::is_zero_time(capacity.observed_at)
        || capacity.observed_at < started_at
        || capacity.observed_at > completed_at
        || capacity.devices.is_empty()
        || capacity.devices.len() > MAXIMUM_RESTORE_ADMISSION_DEVICES
    {
        return Err(restore_admission_unavailable());
    }
    let Some(sealed_bytes) = request.dump_bytes.checked_add(request.object_bytes) else {
        return Err(restore_admission_unavailable());
    };
    let mut seen = std::collections::HashSet::with_capacity(capacity.devices.len());
    let mut planned_total = 0u64;
    for device in &capacity.devices {
        if !valid_restore_admission_fingerprint(&device.device_id)
            || device.planned_bytes == 0
            || !valid_restore_admission_fingerprint(&device.reserve_evidence_digest)
            || !device.reserve_verified
            || !seen.insert(device.device_id.clone())
        {
            return Err(restore_admission_unavailable());
        }
        let Some(next_total) = planned_total.checked_add(device.planned_bytes) else {
            return Err(restore_admission_unavailable());
        };
        planned_total = next_total;
        let Some(required) = restore_admission_margin(device.planned_bytes) else {
            return Err(restore_admission_unavailable());
        };
        if device.available_bytes < required {
            return Err(restore_admission_unavailable());
        }
    }
    if planned_total < sealed_bytes {
        return Err(restore_admission_unavailable());
    }
    Ok(())
}

/// `deviceEvidence` — the canonical JSON member a device contributes
/// to the ticket's capacity evidence digest.
#[derive(Serialize)]
struct DeviceEvidence {
    device_id: String,
    available_bytes: u64,
    planned_bytes: u64,
    reserve_evidence_digest: String,
    reserve_verified: bool,
}

/// `capacityEvidence` — the canonical `central.restore-capacity-
/// evidence/v1` document the digest covers.
#[derive(Serialize)]
struct CapacityEvidence {
    schema_version: String,
    backup_id: String,
    repository_binding_id: String,
    dump_bytes: u64,
    object_bytes: u64,
    artifact_count: u64,
    observed_at: String,
    devices: Vec<DeviceEvidence>,
}

/// `restoreCapacityEvidenceDigest` — SHA-256 over the canonical JSON
/// document binding request and fresh observation; the devices are
/// sorted so the digest does not depend on planner iteration order.
fn restore_capacity_evidence_digest(
    request: &RestoreCapacityRequest,
    capacity: &RestoreCapacityAdmission,
) -> Result<String, Failure> {
    let mut devices: Vec<DeviceEvidence> = capacity
        .devices
        .iter()
        .map(|d| DeviceEvidence {
            device_id: d.device_id.clone(),
            available_bytes: d.available_bytes,
            planned_bytes: d.planned_bytes,
            reserve_evidence_digest: d.reserve_evidence_digest.clone(),
            reserve_verified: d.reserve_verified,
        })
        .collect();
    devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let raw = serde_json::to_vec(&CapacityEvidence {
        schema_version: RESTORE_CAPACITY_EVIDENCE_SCHEMA.into(),
        backup_id: request.backup_id.to_string(),
        repository_binding_id: request.repository_binding_id.to_string(),
        dump_bytes: request.dump_bytes,
        object_bytes: request.object_bytes,
        artifact_count: request.artifact_count,
        observed_at: crate::broker::wire::format_rfc3339_nano(capacity.observed_at),
        devices,
    })
    .map_err(|_| restore_admission_unavailable())?;
    let digest = Sha256::digest(&raw);
    Ok(format!(
        "sha256:{}",
        crate::broker::wire::hex_encode(&digest)
    ))
}

/// `validRestoreAdmissionFingerprint` — a lowercase `sha256:`-prefixed
/// 64-hex-digest string is the only fingerprint shape admission
/// accepts.
pub fn valid_restore_admission_fingerprint(value: &str) -> bool {
    const PREFIX: &str = "sha256:";
    let Some(hex_part) = value.strip_prefix(PREFIX) else {
        return false;
    };
    hex_part.len() == 64
        && value == value.to_lowercase()
        && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::repository::duplicate_descriptor;
    use crate::backup::repository_verifier::RepositoryVerifier;
    use central_backup::backup::capacity::default_recovery_profile;
    use central_backup::backup::inventory::{InventoryEntry, new_inventory_chunk};
    use central_backup::backup::manifest::new_seal_root_manifest;
    use central_backup::backup::operation::{
        BackupPhase, new_backup_accepted_facts, new_backup_operation,
    };
    use central_backup::port::{RecoveryRepositoryVerifier, RestoreAdmissionInspector as _};
    use central_backup::repository::BackupSealCompanion;
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-r6-adm-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        dir
    }

    fn open_dir(path: &Path) -> OwnedFd {
        rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn digest(value: &str) -> String {
        format!(
            "sha256:{}",
            crate::broker::wire::hex_encode(&Sha256::digest(value.as_bytes()))
        )
    }

    struct Fixture {
        dir: PathBuf,
        repository: Repository,
        backup_id: Uuid,
        evidence: RecoveryVerificationEvidence,
        target: RestoreTargetAdmission,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// `newRestoreAdmissionFixture` — the real write→seal path plus one
    /// real verification walk, so the evidence is exactly what the
    /// production verifier produces over the same read-only repository
    /// the inspector binds to.
    fn fixture(sealed: bool) -> Fixture {
        let dir = tempdir("fixture");
        let root = open_dir(&dir);
        let binding =
            crate::backup_repository::initialize_repository_binding(&root, "admission-fixture")
                .unwrap();
        let writer = Repository::from_descriptor(&root, &binding).unwrap();

        let backup_id = Uuid::now_v7();
        let payload_epoch_id = Uuid::now_v7();
        let config_fingerprint = digest("config");
        let target = TargetIdentity {
            system_id: "system".into(),
            database_oid: "1".into(),
            database: "central".into(),
            config_hash: config_fingerprint.clone(),
            epoch: 7,
        };
        let created = time::OffsetDateTime::from_unix_timestamp(1_760_000_000).unwrap();
        let operation =
            new_backup_operation(Uuid::now_v7(), backup_id, target.clone(), created).unwrap();
        let facts = new_backup_accepted_facts(
            created + time::Duration::seconds(1),
            &restore_admission_target_fingerprint(&target, payload_epoch_id),
            &config_fingerprint,
            payload_epoch_id,
            writer.binding_id(),
            &digest("target-lock"),
        )
        .unwrap();
        let operation = operation
            .accept(facts.clone())
            .unwrap()
            .advance(BackupPhase::Dumping, created + time::Duration::seconds(2))
            .unwrap()
            .advance(BackupPhase::Inventory, created + time::Duration::seconds(3))
            .unwrap();
        writer.bind_backup(&operation).unwrap();
        let mut source = std::io::Cursor::new(b"sealed pg_restore custom archive");
        let dump = writer.write_dump(backup_id, &mut source, 1 << 20).unwrap();
        let body = b"sealed artifact body".to_vec();
        let entry = InventoryEntry {
            artifact_id: Uuid::now_v7(),
            checksum: Sha256::digest(&body).into(),
            size: body.len() as i64,
        };
        let chunk = new_inventory_chunk(0, vec![entry]).unwrap();
        let mut body_source = std::io::Cursor::new(body);
        writer
            .write_artifact_body(backup_id, &entry, &mut body_source)
            .unwrap();
        writer.write_chunk(backup_id, &chunk).unwrap();
        let manifest = new_seal_root_manifest(&operation, dump, &[chunk]).unwrap();
        let tree = writer.write_manifest(&manifest).unwrap();
        if sealed {
            let hmac = Sha256::digest(b"test hmac");
            let mut companion = BackupSealCompanion {
                authority_envelope_id: digest("authority"),
                backup_id,
                operation_id: operation.operation_id,
                repository_binding_id: binding.binding_id,
                target_fingerprint: facts.target_fingerprint.clone(),
                config_fingerprint: facts.config_fingerprint.clone(),
                payload_epoch_id: facts.payload_epoch_id,
                root_manifest_digest: manifest.digest,
                file_tree_digest: tree.digest,
                sealed_at: facts.database_time + time::Duration::seconds(1),
                hmac: crate::broker::wire::hex_encode(&hmac),
                digest: [0u8; 32],
            };
            companion.digest = Sha256::digest(companion.canonical_json().unwrap()).into();
            writer.write_seal_companion(&companion).unwrap();
        }
        writer.close().unwrap();

        let reader_root = open_dir(&dir);
        let reader = Repository::read_only_from_descriptor(&reader_root, &binding).unwrap();
        let verified = RepositoryVerifier::new(
            Repository::read_only_from_descriptor(
                duplicate_descriptor(&reader_root).unwrap(),
                &binding,
            )
            .unwrap(),
        );
        let evidence = if sealed {
            verified
                .verify_backup(backup_id, &default_recovery_profile())
                .unwrap()
        } else {
            RecoveryVerificationEvidence {
                operation_id: Uuid::nil(),
                backup_id,
                repository_binding_id: Uuid::nil(),
                manifest_digest: [0u8; 32],
                seal_companion_digest: [0u8; 32],
                file_tree_digest: [0u8; 32],
                repository_manifest_digest: [0u8; 32],
                repository_revision: 0,
                dump: Default::default(),
                artifact_count: 0,
                object_bytes: 0,
                manifest: manifest.clone(),
            }
        };
        Fixture {
            dir,
            repository: reader,
            backup_id,
            evidence,
            target: RestoreTargetAdmission {
                target: target.clone(),
                target_fingerprint: facts.target_fingerprint,
                security_epoch: 2,
                restore_epoch: target.epoch,
                config_fingerprint: facts.config_fingerprint,
                payload_epoch_id: facts.payload_epoch_id,
                database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
                restore_tool_version: RESTORE_ADMISSION_TOOL_VERSION.into(),
            },
        }
    }

    #[derive(Default)]
    struct SealFake {
        calls: Mutex<u32>,
        err: Mutex<Option<Failure>>,
    }
    impl BackupSealVerifier for SealFake {
        fn verify_backup_seal(
            &self,
            _backup_id: Uuid,
            _manifest_digest: [u8; 32],
            _seal_companion_digest: [u8; 32],
            _file_tree_digest: [u8; 32],
            _repository_manifest_digest: [u8; 32],
            _repository_revision: u64,
        ) -> Result<(), Failure> {
            *self.calls.lock().unwrap() += 1;
            if let Some(e) = self.err.lock().unwrap().take() {
                return Err(e);
            }
            Ok(())
        }
    }

    struct TargetFake {
        admission: RestoreTargetAdmission,
        calls: Mutex<u32>,
    }
    impl RestoreTargetAdmissionSource for TargetFake {
        fn read_restore_target_admission(
            &self,
            _backup_id: Uuid,
        ) -> Result<RestoreTargetAdmission, Failure> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.admission.clone())
        }
    }

    #[derive(Default)]
    struct CapacityShared {
        admission: Mutex<Option<RestoreCapacityAdmission>>,
        last: Mutex<Option<RestoreCapacityRequest>>,
        calls: Mutex<u32>,
        auto_stamp: bool,
    }

    /// Cloneable handle: `Box` it for the inspector while the test
    /// keeps the shared counters.
    #[derive(Clone, Default)]
    struct CapacityFake {
        shared: Arc<CapacityShared>,
    }
    impl CapacityFake {
        fn stamped(admission: RestoreCapacityAdmission) -> Self {
            Self {
                shared: Arc::new(CapacityShared {
                    admission: Mutex::new(Some(admission)),
                    auto_stamp: true,
                    ..CapacityShared::default()
                }),
            }
        }
    }
    impl RestoreCapacitySource for CapacityFake {
        fn read_restore_capacity(
            &self,
            request: RestoreCapacityRequest,
        ) -> Result<RestoreCapacityAdmission, Failure> {
            *self.shared.calls.lock().unwrap() += 1;
            *self.shared.last.lock().unwrap() = Some(request);
            let mut admission =
                self.shared
                    .admission
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or(RestoreCapacityAdmission {
                        observed_at: time::OffsetDateTime::UNIX_EPOCH,
                        devices: Vec::new(),
                    });
            if self.shared.auto_stamp {
                admission.observed_at = time::OffsetDateTime::now_utc();
            }
            Ok(admission)
        }
    }

    /// `validRestoreAdmissionCapacity` — one device covering the sealed
    /// bytes exactly at the 1.25× margin.
    fn valid_capacity(f: &Fixture) -> RestoreCapacityAdmission {
        let base = f.evidence.dump.size as u64 + f.evidence.object_bytes;
        let required = restore_admission_margin(base).unwrap();
        RestoreCapacityAdmission {
            observed_at: time::OffsetDateTime::UNIX_EPOCH,
            devices: vec![RestoreDeviceCapacity {
                device_id: digest("device"),
                available_bytes: required,
                planned_bytes: base,
                reserve_evidence_digest: digest("reserve-evidence"),
                reserve_verified: true,
            }],
        }
    }

    fn inspector(
        f: &Fixture,
        seals: Arc<SealFake>,
        capacity: CapacityFake,
    ) -> RepositoryAdmissionInspector {
        new_repository_admission_inspector(
            Repository::read_only_from_descriptor(open_dir(&f.dir), &f.repository.binding())
                .unwrap(),
            seals,
            Arc::new(TargetFake {
                admission: f.target.clone(),
                calls: Mutex::new(0),
            }),
            Box::new(capacity),
            default_recovery_profile(),
        )
        .unwrap()
    }

    #[test]
    fn inspector_checks_sealed_bindings_and_capacity() {
        let fixture = fixture(true);
        let seals = Arc::new(SealFake::default());
        let capacity = CapacityFake::stamped(valid_capacity(&fixture));
        let inspector = inspector(&fixture, seals.clone(), capacity.clone());
        let facts = inspector
            .inspect_restore_admission(fixture.backup_id, &fixture.evidence)
            .unwrap();
        assert_eq!(facts.target, fixture.target.target);
        assert_eq!(facts.target_fingerprint, fixture.target.target_fingerprint);
        assert_eq!(facts.config_fingerprint, fixture.target.config_fingerprint);
        assert_eq!(facts.security_epoch, fixture.target.security_epoch);
        assert_eq!(facts.restore_epoch, fixture.target.restore_epoch);
        assert_eq!(facts.payload_epoch_id, fixture.target.payload_epoch_id);
        assert_eq!(
            facts.database_schema_version,
            fixture.target.database_schema_version
        );
        assert!(valid_restore_admission_fingerprint(
            &facts.capacity_evidence_digest
        ));
        assert_eq!(facts.tool_version, RESTORE_ADMISSION_TOOL_VERSION);
        assert_eq!(*seals.calls.lock().unwrap(), 1);
        assert_eq!(*capacity.shared.calls.lock().unwrap(), 1);
        let last = capacity.shared.last.lock().unwrap().unwrap();
        assert_eq!(last.backup_id, fixture.backup_id);
        assert_eq!(
            last.repository_binding_id,
            fixture.evidence.repository_binding_id
        );
        assert_eq!(last.dump_bytes, fixture.evidence.dump.size as u64);
        assert_eq!(last.object_bytes, fixture.evidence.object_bytes);
        assert_eq!(last.artifact_count, fixture.evidence.artifact_count);
    }

    #[test]
    fn inspector_requires_repository_and_broker_seal() {
        let fixture = fixture(true);
        // A writable handle is refused outright — fresh repository, so
        // the fixture's shared lock is not in play.
        let writable_dir = tempdir("writable");
        let writable_root = open_dir(&writable_dir);
        let binding = crate::backup_repository::initialize_repository_binding(
            &writable_root,
            "admission-writable",
        )
        .unwrap();
        let writer = Repository::from_descriptor(&writable_root, &binding).unwrap();
        assert!(
            new_repository_admission_inspector(
                writer,
                Arc::new(SealFake::default()),
                Arc::new(TargetFake {
                    admission: fixture.target.clone(),
                    calls: Mutex::new(0)
                }),
                Box::new(CapacityFake::default()),
                default_recovery_profile(),
            )
            .is_err()
        );
        // A refusing seal source maps to the unavailable sentinel, not
        // the locator-bearing adapter error.
        let seals = Arc::new(SealFake {
            calls: Mutex::new(0),
            err: Mutex::new(Some(Failure::unavailable(
                "broker",
                "SECRET-LOCATOR /repository/root",
            ))),
        });
        let inspector = inspector(
            &fixture,
            seals,
            CapacityFake::stamped(valid_capacity(&fixture)),
        );
        let err = inspector
            .inspect_restore_admission(fixture.backup_id, &fixture.evidence)
            .unwrap_err();
        assert!(!err.message().contains("SECRET-LOCATOR"));
        assert!(!err.message().contains("/repository/root"));
        let _ = std::fs::remove_dir_all(&writable_dir);
    }

    #[test]
    fn inspector_rejects_binding_mismatch_as_stale() {
        let fixture = fixture(true);
        let mut stale = fixture.target.clone();
        stale.restore_epoch = fixture.target.restore_epoch + 1;
        let inspector = new_repository_admission_inspector(
            Repository::read_only_from_descriptor(
                open_dir(&fixture.dir),
                &fixture.repository.binding(),
            )
            .unwrap(),
            Arc::new(SealFake::default()),
            Arc::new(TargetFake {
                admission: stale,
                calls: Mutex::new(0),
            }),
            Box::new(CapacityFake::stamped(valid_capacity(&fixture))),
            default_recovery_profile(),
        )
        .unwrap();
        let err = inspector
            .inspect_restore_admission(fixture.backup_id, &fixture.evidence)
            .unwrap_err();
        assert_eq!(err.code(), "RESTORE_TARGET_ADMISSION_STALE");
    }

    #[test]
    fn inspector_rejects_every_evidence_edit() {
        let fixture = fixture(true);
        let seals = Arc::new(SealFake::default());
        let inspector = inspector(
            &fixture,
            seals,
            CapacityFake::stamped(valid_capacity(&fixture)),
        );
        // Foreign backup identity.
        assert!(
            inspector
                .inspect_restore_admission(Uuid::now_v7(), &fixture.evidence)
                .is_err()
        );
        // A foreign repository binding edit.
        let mut edited = fixture.evidence.clone();
        edited.repository_binding_id = Uuid::now_v7();
        assert!(
            inspector
                .inspect_restore_admission(fixture.backup_id, &edited)
                .is_err()
        );
        // A fabricated manifest digest.
        let mut edited = fixture.evidence.clone();
        edited.manifest_digest = [0xAA; 32];
        assert!(
            inspector
                .inspect_restore_admission(fixture.backup_id, &edited)
                .is_err()
        );
        // Flat-field inflation never reaches the capacity request.
        let mut edited = fixture.evidence.clone();
        edited.object_bytes += 1;
        assert!(
            inspector
                .inspect_restore_admission(fixture.backup_id, &edited)
                .is_err()
        );
    }

    #[test]
    fn inspector_requires_fresh_per_device_margin() {
        let fixture = fixture(true);
        let base = fixture.evidence.dump.size as u64 + fixture.evidence.object_bytes;
        let required = restore_admission_margin(base).unwrap();
        for admission in [
            // Stale observation stamp.
            RestoreCapacityAdmission {
                observed_at: time::OffsetDateTime::now_utc() - time::Duration::hours(1),
                devices: valid_capacity(&fixture).devices,
            },
            // Below the 1.25× margin.
            RestoreCapacityAdmission {
                observed_at: time::OffsetDateTime::UNIX_EPOCH,
                devices: vec![RestoreDeviceCapacity {
                    device_id: digest("device"),
                    available_bytes: required - 1,
                    planned_bytes: base,
                    reserve_evidence_digest: digest("reserve-evidence"),
                    reserve_verified: true,
                }],
            },
            // Unverified reserve.
            RestoreCapacityAdmission {
                observed_at: time::OffsetDateTime::UNIX_EPOCH,
                devices: vec![RestoreDeviceCapacity {
                    device_id: digest("device"),
                    available_bytes: required,
                    planned_bytes: base,
                    reserve_evidence_digest: digest("reserve-evidence"),
                    reserve_verified: false,
                }],
            },
            // Duplicate device IDs.
            RestoreCapacityAdmission {
                observed_at: time::OffsetDateTime::UNIX_EPOCH,
                devices: vec![
                    RestoreDeviceCapacity {
                        device_id: digest("device"),
                        available_bytes: required,
                        planned_bytes: base,
                        reserve_evidence_digest: digest("a"),
                        reserve_verified: true,
                    },
                    RestoreDeviceCapacity {
                        device_id: digest("device"),
                        available_bytes: required,
                        planned_bytes: base,
                        reserve_evidence_digest: digest("b"),
                        reserve_verified: true,
                    },
                ],
            },
        ] {
            let inspector = inspector(
                &fixture,
                Arc::new(SealFake::default()),
                CapacityFake {
                    shared: Arc::new(CapacityShared {
                        auto_stamp: admission.observed_at == time::OffsetDateTime::UNIX_EPOCH,
                        admission: Mutex::new(Some(admission)),
                        ..CapacityShared::default()
                    }),
                },
            );
            assert!(
                inspector
                    .inspect_restore_admission(fixture.backup_id, &fixture.evidence)
                    .is_err()
            );
        }
    }

    #[test]
    fn sealed_manifest_totals_re_applies_profile_caps() {
        let fixture = fixture(true);
        let profile = default_recovery_profile();
        let (count, bytes) = sealed_manifest_totals(&fixture.evidence.manifest, &profile).unwrap();
        assert_eq!(count, fixture.evidence.artifact_count);
        assert_eq!(bytes, fixture.evidence.object_bytes);
        // A narrower installed profile refuses the same manifest.
        let mut narrow = profile;
        narrow.max_object_bytes = bytes - 1;
        assert!(sealed_manifest_totals(&fixture.evidence.manifest, &narrow).is_err());
        // Narrowing the record cap on a multi-entry single-chunk
        // manifest refuses — and the same manifest passes under the
        // installed profile.
        let entry = |size: i64| InventoryEntry {
            artifact_id: Uuid::now_v7(),
            checksum: [0xAB; 32],
            size,
        };
        let mut multi = fixture.evidence.manifest.clone();
        multi.chunks = vec![new_inventory_chunk(0, vec![entry(10), entry(20), entry(30)]).unwrap()];
        let (count, bytes) = sealed_manifest_totals(&multi, &profile).unwrap();
        assert_eq!((count, bytes), (3, 60));
        let mut narrow_count = profile;
        narrow_count.max_record_count = 2;
        assert!(sealed_manifest_totals(&multi, &narrow_count).is_err());
    }

    #[test]
    fn unsealed_media_never_reaches_admission() {
        let fixture = fixture(false);
        // An unsealed backup fails the media walk itself; feeding the
        // inspector an empty evidence record is refused too.
        assert!(fixture.evidence.manifest_digest == [0u8; 32]);
        let inspector = inspector(
            &fixture,
            Arc::new(SealFake::default()),
            CapacityFake::stamped(valid_capacity(&fixture)),
        );
        assert!(
            inspector
                .inspect_restore_admission(fixture.backup_id, &fixture.evidence)
                .is_err()
        );
    }
}
