//! `restore_capacity_source_linux.go` — `DescriptorRestoreCapacitySource`:
//! fresh descriptor-relative filesystem measurements mapped onto the
//! canonical PG data/WAL/temp/object demand, over helper-selected
//! descriptors. It has no pathname-based fallback: the runtime supplies
//! neither the descriptors nor the roles, only the trusted composition
//! hands both over.

#![forbid(unsafe_code)]

use central_backup::backup::capacity::{
    SUPPORTED_RECOVERY_DATABASE_BYTES, SUPPORTED_RECOVERY_OBJECT_BYTES,
    SUPPORTED_RECOVERY_RECORD_COUNT, SURVIVAL_RESERVE_BYTES, restore_capacity_demands,
};
use central_foundation::failure::Failure;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use uuid::Uuid;

use super::restore_admission::{
    RestoreCapacityAdmission, RestoreCapacityRequest, RestoreCapacitySource, RestoreDeviceCapacity,
    restore_admission_unavailable, valid_restore_admission_fingerprint,
};

/// `RestoreCapacityReserveReceiptSchema`.
pub const RESTORE_CAPACITY_RESERVE_RECEIPT_SCHEMA: &str =
    "central.restore-capacity-reserve-receipt/v1";

/// `RestoreCapacityRole` — the canonical role a helper-selected
/// descriptor measures. The runtime never chooses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RestoreCapacityRole {
    /// `postgres_data`.
    PostgresData,
    /// `postgres_wal`.
    PostgresWal,
    /// `postgres_temp`.
    PostgresTemp,
    /// `object_data`.
    ObjectData,
}

impl RestoreCapacityRole {
    /// The wire role string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostgresData => "postgres_data",
            Self::PostgresWal => "postgres_wal",
            Self::PostgresTemp => "postgres_temp",
            Self::ObjectData => "object_data",
        }
    }

    /// Parse a wire role string; unknown values are `None`.
    #[must_use]
    pub fn parse(role: &str) -> Option<Self> {
        Some(match role {
            "postgres_data" => Self::PostgresData,
            "postgres_wal" => Self::PostgresWal,
            "postgres_temp" => Self::PostgresTemp,
            "object_data" => Self::ObjectData,
            _ => return None,
        })
    }
}

/// `restoreCapacityRoles` — every descriptor the source requires.
const RESTORE_CAPACITY_ROLES: [RestoreCapacityRole; 4] = [
    RestoreCapacityRole::PostgresData,
    RestoreCapacityRole::PostgresWal,
    RestoreCapacityRole::PostgresTemp,
    RestoreCapacityRole::ObjectData,
];

/// `RestoreCapacityReserveReceipt` — helper-issued, locator-free proof
/// that the survival reserve for one exact role/device/request is
/// already allocated. `authority_proof` is consumed only by the
/// verifier and never enters admission facts, tickets, diagnostics, or
/// the capacity evidence digest.
#[derive(Debug, Clone)]
pub struct RestoreCapacityReserveReceipt {
    /// `central.restore-capacity-reserve-receipt/v1`.
    pub schema_version: String,
    /// Receipt identity (v7).
    pub receipt_id: Uuid,
    /// Sealed backup this reserve binds.
    pub backup_id: Uuid,
    /// Repository binding this reserve binds.
    pub repository_binding_id: Uuid,
    /// Capacity role the reserve covers.
    pub role: RestoreCapacityRole,
    /// `sha256:`-prefixed opaque mount identity.
    pub device_id: String,
    /// Allocated reserve bytes.
    pub reserved_bytes: u64,
    /// Issue instant.
    pub issued_at: time::OffsetDateTime,
    /// Expiry instant.
    pub expires_at: time::OffsetDateTime,
    /// Verifier-only authority proof.
    pub authority_proof: String,
}

/// `RestoreCapacityDescriptor` — selected by trusted helper
/// composition. The runtime supplies neither its descriptor nor its
/// role; the source duplicates the supplied descriptor so the caller's
/// remains owned by the caller.
pub struct RestoreCapacityDescriptor<Fd: AsFd> {
    /// Canonical capacity role.
    pub role: RestoreCapacityRole,
    /// Helper-authorized directory descriptor for the role root.
    pub fd: Fd,
    /// The reserve receipt bound to this role and request.
    pub reserve: RestoreCapacityReserveReceipt,
}

/// `RestoreCapacityReserveVerifier` — verifies the helper-issued
/// reserve receipt's authority proof.
pub trait RestoreCapacityReserveVerifier: Send + Sync {
    /// `VerifyRestoreCapacityReserve`.
    fn verify_restore_capacity_reserve(
        &self,
        receipt: &RestoreCapacityReserveReceipt,
    ) -> Result<(), Failure>;
}

/// `DescriptorRestoreCapacitySource` — see the module header. Owns a
/// duplicate of each helper descriptor; the caller's stays live.
pub struct DescriptorRestoreCapacitySource {
    descriptors: Vec<(RestoreCapacityRole, OwnedFd, RestoreCapacityReserveReceipt)>,
    verifier: Arc<dyn RestoreCapacityReserveVerifier>,
    now: Box<dyn Fn() -> time::OffsetDateTime + Send + Sync>,
}

/// `NewDescriptorRestoreCapacitySource` — requires exactly one
/// descriptor per canonical role, each receipt bound to its role.
pub fn new_descriptor_restore_capacity_source<Fd: AsFd>(
    descriptors: Vec<RestoreCapacityDescriptor<Fd>>,
    verifier: Arc<dyn RestoreCapacityReserveVerifier>,
) -> Result<DescriptorRestoreCapacitySource, Failure> {
    if descriptors.len() != RESTORE_CAPACITY_ROLES.len() {
        return Err(restore_admission_unavailable());
    }
    let mut seen = std::collections::HashSet::with_capacity(descriptors.len());
    let mut owned = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        if !RESTORE_CAPACITY_ROLES.contains(&descriptor.role)
            || descriptor.reserve.role != descriptor.role
            || !seen.insert(descriptor.role)
        {
            return Err(restore_admission_unavailable());
        }
        let fd = super::repository::duplicate_descriptor(&descriptor.fd)
            .map_err(|_| restore_admission_unavailable())?;
        owned.push((descriptor.role, fd, descriptor.reserve));
    }
    Ok(DescriptorRestoreCapacitySource {
        descriptors: owned,
        verifier,
        now: Box::new(time::OffsetDateTime::now_utc),
    })
}

impl DescriptorRestoreCapacitySource {
    /// Test seam — override the observation clock.
    #[cfg(test)]
    pub(crate) fn set_now(
        &mut self,
        now: impl Fn() -> time::OffsetDateTime + Send + Sync + 'static,
    ) {
        self.now = Box::new(now);
    }
}

impl RestoreCapacitySource for DescriptorRestoreCapacitySource {
    /// `ReadRestoreCapacity` — validates the request, verifies every
    /// reserve receipt, measures each role descriptor, and aggregates
    /// the per-device plan.
    fn read_restore_capacity(
        &self,
        request: RestoreCapacityRequest,
    ) -> Result<RestoreCapacityAdmission, Failure> {
        if request.backup_id.is_nil()
            || request.backup_id.get_version_num() != 7
            || request.repository_binding_id.is_nil()
            || request.dump_bytes == 0
            || request.dump_bytes > SUPPORTED_RECOVERY_DATABASE_BYTES
            || request.object_bytes > SUPPORTED_RECOVERY_OBJECT_BYTES
            || request.artifact_count > SUPPORTED_RECOVERY_RECORD_COUNT
        {
            return Err(restore_admission_unavailable());
        }
        let demand = restore_capacity_demands(
            request.dump_bytes,
            request.object_bytes,
            request.artifact_count,
        )
        .ok_or_else(restore_admission_unavailable)?;
        let demands = [
            (
                RestoreCapacityRole::PostgresData,
                demand.postgres_data_bytes,
            ),
            (RestoreCapacityRole::PostgresWal, demand.postgres_wal_bytes),
            (
                RestoreCapacityRole::PostgresTemp,
                demand.postgres_temp_bytes,
            ),
            (RestoreCapacityRole::ObjectData, demand.object_data_bytes),
        ];
        #[derive(Default)]
        struct Aggregate {
            available: u64,
            planned: u64,
        }
        let mut by_device: std::collections::HashMap<String, Aggregate> =
            std::collections::HashMap::with_capacity(self.descriptors.len());
        let mut reserve_evidence: std::collections::HashMap<
            String,
            Vec<RestoreCapacityReserveReceipt>,
        > = std::collections::HashMap::with_capacity(self.descriptors.len());
        let mut earliest_reserve_expiry: Option<time::OffsetDateTime> = None;
        for (role, fd, receipt) in &self.descriptors {
            let now = (self.now)().to_offset(time::UtcOffset::UTC);
            if !valid_restore_capacity_reserve_receipt(receipt, &request, *role, now)
                || self
                    .verifier
                    .verify_restore_capacity_reserve(receipt)
                    .is_err()
            {
                return Err(restore_admission_unavailable());
            }
            if earliest_reserve_expiry.is_none_or(|e| receipt.expires_at < e) {
                earliest_reserve_expiry = Some(receipt.expires_at);
            }
            let measurement = super::capacity::device_capacity_from_descriptor(fd)
                .map_err(|_| restore_admission_unavailable())?;
            let device_id = restore_capacity_device_id(&measurement.device_id);
            if device_id != receipt.device_id {
                return Err(restore_admission_unavailable());
            }
            let planned = demands
                .iter()
                .find(|(r, _)| r == role)
                .map(|(_, b)| *b)
                .unwrap_or(0);
            if planned == 0 {
                continue;
            }
            reserve_evidence
                .entry(device_id.clone())
                .or_default()
                .push(receipt.clone());
            let current = by_device.entry(device_id.clone()).or_insert(Aggregate {
                available: measurement.free_bytes,
                planned: 0,
            });
            if measurement.free_bytes < current.available {
                current.available = measurement.free_bytes;
            }
            current.planned = current
                .planned
                .checked_add(planned)
                .ok_or_else(restore_admission_unavailable)?;
        }
        if by_device.is_empty() {
            return Err(restore_admission_unavailable());
        }
        let mut devices = Vec::with_capacity(by_device.len());
        for (device_id, capacity) in by_device {
            let reserve_digest =
                restore_capacity_reserve_evidence_digest(&reserve_evidence[&device_id])?;
            devices.push(RestoreDeviceCapacity {
                device_id,
                available_bytes: capacity.available,
                planned_bytes: capacity.planned,
                reserve_evidence_digest: reserve_digest,
                reserve_verified: true,
            });
        }
        devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let observed_at = (self.now)().to_offset(time::UtcOffset::UTC);
        let Some(earliest_reserve_expiry) = earliest_reserve_expiry else {
            return Err(restore_admission_unavailable());
        };
        if observed_at >= earliest_reserve_expiry {
            return Err(restore_admission_unavailable());
        }
        Ok(RestoreCapacityAdmission {
            observed_at,
            devices,
        })
    }
}

/// `receiptEvidence` — the canonical JSON member a receipt contributes
/// to the per-device reserve evidence digest. `authority_proof` is
/// deliberately absent.
#[derive(Serialize)]
struct ReceiptEvidence {
    schema_version: String,
    receipt_id: String,
    backup_id: String,
    repository_binding_id: String,
    role: String,
    device_id: String,
    reserved_bytes: u64,
    issued_at: String,
    expires_at: String,
}

/// `restoreCapacityReserveEvidenceDigest` — SHA-256 over the canonical
/// receipt list (sorted by role, then receipt ID).
fn restore_capacity_reserve_evidence_digest(
    receipts: &[RestoreCapacityReserveReceipt],
) -> Result<String, Failure> {
    let mut canonical: Vec<ReceiptEvidence> = receipts
        .iter()
        .map(|r| ReceiptEvidence {
            schema_version: r.schema_version.clone(),
            receipt_id: r.receipt_id.to_string(),
            backup_id: r.backup_id.to_string(),
            repository_binding_id: r.repository_binding_id.to_string(),
            role: r.role.as_str().into(),
            device_id: r.device_id.clone(),
            reserved_bytes: r.reserved_bytes,
            issued_at: crate::broker::wire::format_rfc3339_nano(r.issued_at),
            expires_at: crate::broker::wire::format_rfc3339_nano(r.expires_at),
        })
        .collect();
    canonical.sort_by(|a, b| {
        a.role
            .cmp(&b.role)
            .then_with(|| a.receipt_id.cmp(&b.receipt_id))
    });
    let raw = serde_json::to_vec(&canonical).map_err(|_| restore_admission_unavailable())?;
    let digest = Sha256::digest(&raw);
    Ok(format!(
        "sha256:{}",
        crate::broker::wire::hex_encode(&digest)
    ))
}

/// `validRestoreCapacityReserveReceipt` — schema, v7 identities,
/// request/role binding, reserve floor, validity window, and a
/// present authority proof.
fn valid_restore_capacity_reserve_receipt(
    receipt: &RestoreCapacityReserveReceipt,
    request: &RestoreCapacityRequest,
    role: RestoreCapacityRole,
    now: time::OffsetDateTime,
) -> bool {
    receipt.schema_version == RESTORE_CAPACITY_RESERVE_RECEIPT_SCHEMA
        && !receipt.receipt_id.is_nil()
        && receipt.receipt_id.get_version_num() == 7
        && receipt.backup_id == request.backup_id
        && receipt.repository_binding_id == request.repository_binding_id
        && receipt.role == role
        && valid_restore_admission_fingerprint(&receipt.device_id)
        && receipt.reserved_bytes >= SURVIVAL_RESERVE_BYTES
        && !super::environment::is_zero_time(receipt.issued_at)
        && !super::environment::is_zero_time(receipt.expires_at)
        && receipt.expires_at >= receipt.issued_at
        && now >= receipt.issued_at
        && now < receipt.expires_at
        && !receipt.authority_proof.is_empty()
}

/// `restoreCapacityDeviceID` — SHA-256 over the opaque filesystem ID;
/// the raw `fs-…` value never enters admission evidence.
#[must_use]
pub fn restore_capacity_device_id(opaque_filesystem_id: &str) -> String {
    let digest = Sha256::digest(opaque_filesystem_id.as_bytes());
    format!("sha256:{}", crate::broker::wire::hex_encode(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "central-r6-rcap-{tag}-{}-{}",
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

    const NOW: i64 = 1_760_000_000;
    fn now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(NOW).unwrap()
    }

    fn request() -> RestoreCapacityRequest {
        RestoreCapacityRequest {
            backup_id: Uuid::now_v7(),
            repository_binding_id: Uuid::now_v7(),
            dump_bytes: 4096,
            object_bytes: 2048,
            artifact_count: 2,
        }
    }

    fn receipt(
        request: &RestoreCapacityRequest,
        role: RestoreCapacityRole,
        device_id: &str,
    ) -> RestoreCapacityReserveReceipt {
        RestoreCapacityReserveReceipt {
            schema_version: RESTORE_CAPACITY_RESERVE_RECEIPT_SCHEMA.into(),
            receipt_id: Uuid::now_v7(),
            backup_id: request.backup_id,
            repository_binding_id: request.repository_binding_id,
            role,
            device_id: device_id.into(),
            reserved_bytes: SURVIVAL_RESERVE_BYTES,
            issued_at: now() - time::Duration::minutes(1),
            expires_at: now() + time::Duration::hours(1),
            authority_proof: "proof".into(),
        }
    }

    fn descriptors<'a>(
        fd: &'a OwnedFd,
        request: &RestoreCapacityRequest,
        device_id: &str,
    ) -> Vec<RestoreCapacityDescriptor<&'a OwnedFd>> {
        RESTORE_CAPACITY_ROLES
            .iter()
            .map(|role| RestoreCapacityDescriptor {
                role: *role,
                fd,
                reserve: receipt(request, *role, device_id),
            })
            .collect()
    }

    #[derive(Default)]
    struct VerifierFake {
        calls: Mutex<u32>,
        refuse: bool,
    }
    impl RestoreCapacityReserveVerifier for VerifierFake {
        fn verify_restore_capacity_reserve(
            &self,
            _receipt: &RestoreCapacityReserveReceipt,
        ) -> Result<(), Failure> {
            *self.calls.lock().unwrap() += 1;
            if self.refuse {
                return Err(Failure::denied("reserve", "SECRET-LOCATOR /reserve"));
            }
            Ok(())
        }
    }

    struct Setup {
        dir: PathBuf,
        request: RestoreCapacityRequest,
        device_id: String,
    }
    impl Drop for Setup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn setup() -> (Setup, OwnedFd) {
        let dir = tempdir("source");
        let fd = open_dir(&dir);
        let measurement = super::super::capacity::device_capacity_from_descriptor(&fd).unwrap();
        (
            Setup {
                dir,
                request: request(),
                device_id: restore_capacity_device_id(&measurement.device_id),
            },
            fd,
        )
    }

    #[test]
    fn source_reads_fresh_capacity_for_every_role() {
        let (setup, fd) = setup();
        let verifier = Arc::new(VerifierFake::default());
        let mut source = new_descriptor_restore_capacity_source(
            descriptors(&fd, &setup.request, &setup.device_id),
            verifier.clone(),
        )
        .unwrap();
        source.set_now(now);
        let admission = source.read_restore_capacity(setup.request).unwrap();
        assert_eq!(admission.observed_at, now());
        assert_eq!(admission.devices.len(), 1);
        let device = &admission.devices[0];
        assert_eq!(device.device_id, setup.device_id);
        // Free bytes move under concurrent tests; only nonzero is
        // pinned (upstream asserts the same).
        assert!(device.available_bytes > 0);
        let demand = restore_capacity_demands(
            setup.request.dump_bytes,
            setup.request.object_bytes,
            setup.request.artifact_count,
        )
        .unwrap();
        let planned = demand.postgres_data_bytes
            + demand.postgres_wal_bytes
            + demand.postgres_temp_bytes
            + demand.object_data_bytes;
        assert_eq!(device.planned_bytes, planned);
        assert!(valid_restore_admission_fingerprint(
            &device.reserve_evidence_digest
        ));
        assert!(device.reserve_verified);
        assert_eq!(*verifier.calls.lock().unwrap(), 4);
    }

    #[test]
    fn source_refuses_invalid_receipts_and_verifier_refusal() {
        let (setup, fd) = setup();
        for mutate in [
            // Receipt naming a different device.
            Box::new(|r: &mut RestoreCapacityReserveReceipt| {
                r.device_id = restore_capacity_device_id("fs-other-device");
            }) as Box<dyn Fn(&mut RestoreCapacityReserveReceipt)>,
            // Expired reserve.
            Box::new(|r: &mut RestoreCapacityReserveReceipt| {
                r.expires_at = now() - time::Duration::seconds(1);
            }),
            // Missing authority proof.
            Box::new(|r: &mut RestoreCapacityReserveReceipt| {
                r.authority_proof.clear();
            }),
            // Reserve below the survival floor.
            Box::new(|r: &mut RestoreCapacityReserveReceipt| {
                r.reserved_bytes = SURVIVAL_RESERVE_BYTES - 1;
            }),
            // Wrong schema.
            Box::new(|r: &mut RestoreCapacityReserveReceipt| {
                r.schema_version = "other-schema".into();
            }),
            // Foreign request binding.
            Box::new(|r: &mut RestoreCapacityReserveReceipt| {
                r.backup_id = Uuid::now_v7();
            }),
        ] {
            let mut descriptors = descriptors(&fd, &setup.request, &setup.device_id);
            mutate(&mut descriptors[0].reserve);
            let mut source = new_descriptor_restore_capacity_source(
                descriptors,
                Arc::new(VerifierFake::default()),
            )
            .unwrap();
            source.set_now(now);
            assert!(source.read_restore_capacity(setup.request).is_err());
        }
        // A refusing verifier maps to the unavailable sentinel, not the
        // locator-bearing adapter error.
        let mut source = new_descriptor_restore_capacity_source(
            descriptors(&fd, &setup.request, &setup.device_id),
            Arc::new(VerifierFake {
                calls: Mutex::new(0),
                refuse: true,
            }),
        )
        .unwrap();
        source.set_now(now);
        let err = source.read_restore_capacity(setup.request).unwrap_err();
        assert!(!err.message().contains("SECRET-LOCATOR"));
        assert!(!err.message().contains("/reserve"));
    }

    #[test]
    fn constructor_and_request_bounds_refuse() {
        let (setup, fd) = setup();
        // Missing a role.
        let mut short = descriptors(&fd, &setup.request, &setup.device_id);
        short.pop();
        assert!(
            new_descriptor_restore_capacity_source(short, Arc::new(VerifierFake::default()),)
                .is_err()
        );
        // Duplicate role.
        let mut duplicate = descriptors(&fd, &setup.request, &setup.device_id);
        duplicate[3].role = RestoreCapacityRole::PostgresData;
        assert!(
            new_descriptor_restore_capacity_source(duplicate, Arc::new(VerifierFake::default()),)
                .is_err()
        );
        // Receipt bound to a different role than its descriptor.
        let mut mismatched = descriptors(&fd, &setup.request, &setup.device_id);
        mismatched[0].reserve.role = RestoreCapacityRole::PostgresWal;
        assert!(
            new_descriptor_restore_capacity_source(mismatched, Arc::new(VerifierFake::default()),)
                .is_err()
        );
        // Request bounds.
        let mut source = new_descriptor_restore_capacity_source(
            descriptors(&fd, &setup.request, &setup.device_id),
            Arc::new(VerifierFake::default()),
        )
        .unwrap();
        source.set_now(now);
        for request in [
            RestoreCapacityRequest {
                backup_id: Uuid::nil(),
                ..setup.request
            },
            RestoreCapacityRequest {
                dump_bytes: 0,
                ..setup.request
            },
            RestoreCapacityRequest {
                dump_bytes: SUPPORTED_RECOVERY_DATABASE_BYTES + 1,
                ..setup.request
            },
            RestoreCapacityRequest {
                artifact_count: SUPPORTED_RECOVERY_RECORD_COUNT + 1,
                ..setup.request
            },
        ] {
            assert!(source.read_restore_capacity(request).is_err());
        }
    }
}
