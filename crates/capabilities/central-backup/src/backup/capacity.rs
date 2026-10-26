//! `internal/backup/recovery.go` — the C02 admission profile and its
//! capacity arithmetic: `RecoveryProfile`, the device/repository
//! census, `CheckBackupAdmission`, `CheckBackupContinuation`, the
//! media-verification and restore-run deadline derivations,
//! `RestoreCapacityDemands`, `RestoreAdmissionMargin` and `RoleRoots`.

use central_foundation::failure::{Failure, FailureKind};

use super::operation::BackupOperation;

const MEBIBYTE: u64 = 1024 * 1024;
const GIBIBYTE: u64 = 1024 * MEBIBYTE;

/// Supported Phase 1 recovery profile bounds (`SupportedRecovery*`).
pub const SUPPORTED_RECOVERY_DATABASE_BYTES: u64 = 5 * GIBIBYTE;
/// `SupportedRecoveryObjectBytes`.
pub const SUPPORTED_RECOVERY_OBJECT_BYTES: u64 = 10 * GIBIBYTE;
/// `SupportedRecoveryRecordCount`.
pub const SUPPORTED_RECOVERY_RECORD_COUNT: u64 = 10_000;
/// `MinimumRecoveryThroughputBPS`.
pub const MINIMUM_RECOVERY_THROUGHPUT_BPS: u64 = 16 * MEBIBYTE;
/// `SurvivalReserveBytes`.
pub const SURVIVAL_RESERVE_BYTES: u64 = 4 * GIBIBYTE;
/// `FreeFloorBytes`.
pub const FREE_FLOOR_BYTES: u64 = GIBIBYTE;
/// `WriteQuantumBytes`.
pub const WRITE_QUANTUM_BYTES: u64 = 8 * MEBIBYTE;
/// `MaximumSealedBackups` (u64 form; `repository::MAXIMUM_SEALED_BACKUPS`
/// is the usize for slice bounds).
pub const MAXIMUM_SEALED_BACKUPS: u64 = 16;
/// `MaximumRepositoryBytes`.
pub const MAXIMUM_REPOSITORY_BYTES: u64 = 256 * GIBIBYTE;
/// `MaximumSealRootManifestBytes`.
pub const MAXIMUM_SEAL_ROOT_MANIFEST_BYTES: u64 = 4 * MEBIBYTE;
/// `MinimumDumpProbeArchiveBytes`.
pub const MINIMUM_DUMP_PROBE_ARCHIVE_BYTES: u64 = 512 * MEBIBYTE;
/// `MaximumDumpProbeArchiveBytes`.
pub const MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES: u64 = 544 * MEBIBYTE;
/// `ObjectProbePayloadBytes`.
pub const OBJECT_PROBE_PAYLOAD_BYTES: u64 = 512 * MEBIBYTE;
/// `MinimumDumpEstimateBytes`.
pub const MINIMUM_DUMP_ESTIMATE_BYTES: u64 = GIBIBYTE;
/// `InventoryRecordBoundBytes`.
pub const INVENTORY_RECORD_BOUND_BYTES: u64 = 4096;
/// `InventoryChunkBoundBytes`.
pub const INVENTORY_CHUNK_BOUND_BYTES: u64 = 64 * 1024;
/// `InventoryFixedBoundBytes`.
pub const INVENTORY_FIXED_BOUND_BYTES: u64 = MEBIBYTE;
/// `MaximumInventoryChunkEntries`.
pub const MAXIMUM_INVENTORY_CHUNK_ENTRIES: u64 = 1_000;

/// `DefaultRecoveryDeadline` — two hours.
pub const DEFAULT_RECOVERY_DEADLINE: time::Duration = time::Duration::hours(2);
/// `MaximumRecoveryDeadline` — eight hours.
pub const MAXIMUM_RECOVERY_DEADLINE: time::Duration = time::Duration::hours(8);
/// `ThroughputEvidenceMaxAge` — seven days.
pub const THROUGHPUT_EVIDENCE_MAX_AGE: time::Duration = time::Duration::hours(7 * 24);
/// `MaximumThroughputProbeElapsed` — five minutes.
pub const MAXIMUM_THROUGHPUT_PROBE_ELAPSED: time::Duration = time::Duration::minutes(5);

/// `MediaVerificationMarginNumerator`/`Denominator` — the 25% margin.
pub const MEDIA_VERIFICATION_MARGIN_NUMERATOR: u64 = 5;
/// See [`MEDIA_VERIFICATION_MARGIN_NUMERATOR`].
pub const MEDIA_VERIFICATION_MARGIN_DENOMINATOR: u64 = 4;

/// `RecoveryProfile` — the installed admission envelope. It may
/// narrow, never widen, the supported local reference profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryProfile {
    /// `MaxDatabaseBytes`.
    pub max_database_bytes: u64,
    /// `MaxObjectBytes`.
    pub max_object_bytes: u64,
    /// `MaxRecordCount`.
    pub max_record_count: u64,
    /// `MinThroughputBPS`.
    pub min_throughput_bps: u64,
    /// `SurvivalReserve`.
    pub survival_reserve: u64,
    /// `FreeFloor`.
    pub free_floor: u64,
    /// `WriteQuantum`.
    pub write_quantum: u64,
    /// `MaxSealedBackups`.
    pub max_sealed_backups: u64,
    /// `MaxRepositoryBytes`.
    pub max_repository_bytes: u64,
    /// `DefaultDeadline`.
    pub default_deadline: time::Duration,
    /// `MaximumDeadline`.
    pub maximum_deadline: time::Duration,
    /// `ThroughputMaxAge`.
    pub throughput_max_age: time::Duration,
}

/// `DefaultRecoveryProfile` — the accepted Phase 1 local profile.
#[must_use]
pub fn default_recovery_profile() -> RecoveryProfile {
    RecoveryProfile {
        max_database_bytes: SUPPORTED_RECOVERY_DATABASE_BYTES,
        max_object_bytes: SUPPORTED_RECOVERY_OBJECT_BYTES,
        max_record_count: SUPPORTED_RECOVERY_RECORD_COUNT,
        min_throughput_bps: MINIMUM_RECOVERY_THROUGHPUT_BPS,
        survival_reserve: SURVIVAL_RESERVE_BYTES,
        free_floor: FREE_FLOOR_BYTES,
        write_quantum: WRITE_QUANTUM_BYTES,
        max_sealed_backups: MAXIMUM_SEALED_BACKUPS,
        max_repository_bytes: MAXIMUM_REPOSITORY_BYTES,
        default_deadline: DEFAULT_RECOVERY_DEADLINE,
        maximum_deadline: MAXIMUM_RECOVERY_DEADLINE,
        throughput_max_age: THROUGHPUT_EVIDENCE_MAX_AGE,
    }
}

impl RecoveryProfile {
    /// `Validate` — refuses zero, inconsistent, or broadened recovery
    /// configuration. Upstream returns a plain error (never an
    /// `AdmissionFailure`): an invalid profile is a configuration
    /// defect, not a pre-mutation refusal.
    pub fn validate(&self) -> Result<(), Failure> {
        let invalid = |message: &'static str| Failure::invalid("recovery_profile_invalid", message);
        if self.max_database_bytes == 0
            || self.max_database_bytes > SUPPORTED_RECOVERY_DATABASE_BYTES
        {
            return Err(invalid("invalid recovery database-byte limit"));
        }
        if self.max_object_bytes == 0 || self.max_object_bytes > SUPPORTED_RECOVERY_OBJECT_BYTES {
            return Err(invalid("invalid recovery object-byte limit"));
        }
        if self.max_record_count == 0 || self.max_record_count > SUPPORTED_RECOVERY_RECORD_COUNT {
            return Err(invalid("invalid recovery record-count limit"));
        }
        if self.min_throughput_bps < MINIMUM_RECOVERY_THROUGHPUT_BPS {
            return Err(invalid(
                "recovery minimum throughput weakens the supported profile",
            ));
        }
        if self.survival_reserve < SURVIVAL_RESERVE_BYTES
            || self.free_floor < FREE_FLOOR_BYTES
            || self.write_quantum == 0
            || self.write_quantum > WRITE_QUANTUM_BYTES
        {
            return Err(invalid("invalid recovery capacity guard"));
        }
        if self.max_sealed_backups == 0
            || self.max_sealed_backups > MAXIMUM_SEALED_BACKUPS
            || self.max_repository_bytes == 0
            || self.max_repository_bytes > MAXIMUM_REPOSITORY_BYTES
        {
            return Err(invalid("invalid recovery repository limit"));
        }
        if self.default_deadline <= time::Duration::ZERO
            || self.default_deadline > self.maximum_deadline
            || self.maximum_deadline > MAXIMUM_RECOVERY_DEADLINE
        {
            return Err(invalid("invalid recovery deadline"));
        }
        if self.throughput_max_age <= time::Duration::ZERO
            || self.throughput_max_age > THROUGHPUT_EVIDENCE_MAX_AGE
        {
            return Err(invalid("invalid recovery throughput-evidence lifetime"));
        }
        Ok(())
    }

    /// `MediaVerificationDeadline` — the honest wall-clock bound for
    /// `walks` full SHA-256 walks of the supported recovery media,
    /// plus margin, clamped to `maximum_deadline`. Returns `None` for
    /// an invalid profile, no walks, or overflow — a caller that
    /// cannot derive a bound refuses instead of running unbounded.
    #[must_use]
    pub fn media_verification_deadline(&self, walks: u64) -> Option<time::Duration> {
        if self.validate().is_err() || walks == 0 || self.min_throughput_bps == 0 {
            return None;
        }
        let media_bytes = self.max_database_bytes.checked_add(self.max_object_bytes)?;
        let total = media_bytes.checked_mul(walks)?;
        let seconds = total.div_ceil(self.min_throughput_bps);
        if seconds > MAXIMUM_RECOVERY_DEADLINE.whole_seconds() as u64 {
            return Some(self.maximum_deadline);
        }
        let margin =
            seconds * MEDIA_VERIFICATION_MARGIN_NUMERATOR / MEDIA_VERIFICATION_MARGIN_DENOMINATOR;
        let deadline = time::Duration::seconds(margin as i64);
        if deadline > self.maximum_deadline {
            return Some(self.maximum_deadline);
        }
        Some(deadline)
    }

    /// `RestoreRunDeadline` — `default_deadline + ceremony`, clamped to
    /// `maximum_deadline` (the clamp shortens the engine share, never
    /// the ceremony). Returns `None` for an invalid profile, a
    /// non-positive ceremony, or overflow.
    #[must_use]
    pub fn restore_run_deadline(&self, ceremony: time::Duration) -> Option<time::Duration> {
        if self.validate().is_err() || ceremony <= time::Duration::ZERO {
            return None;
        }
        let deadline = self.default_deadline.checked_add(ceremony)?;
        if deadline > self.maximum_deadline {
            return Some(self.maximum_deadline);
        }
        Some(deadline)
    }
}

/// `DeviceCapacitySnapshot` — one writable-device reading. `device_id`
/// is the opaque helper-derived mount/device identity, never a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCapacitySnapshot {
    /// Opaque device identity.
    pub device_id: String,
    /// Free bytes measured on that device.
    pub free_bytes: u64,
}

/// `CapacitySnapshot` — measured quantities only; never a path,
/// credential, object key, or locator. The device census must include
/// every writable device used by dump, repository, and object-copy
/// phases; one unsafe device blocks the operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapacitySnapshot {
    /// One reading per writable device.
    pub devices: Vec<DeviceCapacitySnapshot>,
    /// Total recovery-repository bytes already committed.
    pub repository_bytes: u64,
    /// Sealed backups already held.
    pub sealed_backups: u64,
    /// Live database bytes the dump will carry.
    pub database_bytes: u64,
    /// Live object bytes the inventory will carry.
    pub object_bytes: u64,
    /// Live record count the inventory will enumerate.
    pub record_count: u64,
}

/// The typed refusal `CheckBackupAdmission` returns — upstream's three
/// distinct error shapes kept as one enum so `errors.As`
/// classification survives the Rust port:
///
/// - [`BackupCheck::Profile`] ≙ the plain `error` an invalid
///   [`RecoveryProfile`] or malformed input produces — a
///   configuration defect, not a refusal;
/// - [`BackupCheck::Diagnostic`] ≙ `ProfileDiagnostic` — the request
///   is outside the supported profile; callers must make no write;
/// - [`BackupCheck::Admission`] ≙ `AdmissionFailure` — a safe
///   pre-mutation rejection carrying only its closed reason.
#[derive(Debug, Clone)]
pub enum BackupCheck {
    /// Upstream plain `error` (invalid profile/inputs).
    Profile(Failure),
    /// `ProfileDiagnostic{Reason}` — outside the supported profile.
    Diagnostic(String),
    /// `AdmissionFailure{Reason}` — refused before any mutation.
    Admission(String),
}

impl BackupCheck {
    /// `IsAdmissionFailure(err, reason)` for the typed refusal.
    #[must_use]
    pub fn is_admission(&self, reason: &str) -> bool {
        matches!(self, Self::Admission(r) if r == reason)
    }

    /// `IsProfileDiagnostic` — the "outside-profile warning" class.
    #[must_use]
    pub fn is_diagnostic(&self) -> bool {
        matches!(self, Self::Diagnostic(_))
    }

    /// `IsProfileDiagnostic(err)` where the reason must also match.
    #[must_use]
    pub fn is_diagnostic_of(&self, reason: &str) -> bool {
        matches!(self, Self::Diagnostic(r) if r == reason)
    }

    /// Renders the check as the layer's [`Failure`]: diagnostics and
    /// admission refusals are operator-facing denials carrying the
    /// upstream reason as the machine code; a profile defect is the
    /// [`Failure`] it already is.
    #[must_use]
    pub fn into_failure(&self) -> Failure {
        match self {
            Self::Profile(failure) => failure.clone(),
            Self::Diagnostic(reason) => Failure::new(
                FailureKind::Denied,
                reason_code(reason),
                format!("recovery admission diagnostic: {reason}"),
            ),
            Self::Admission(reason) => Failure::new(
                FailureKind::Denied,
                reason_code(reason),
                format!("recovery admission refused: {reason}"),
            ),
        }
    }
}

fn reason_code(reason: &str) -> &'static str {
    // Reasons are a closed vocabulary of uppercase names; keep the
    // stable string as the machine code.
    match reason {
        "OUTSIDE_SUPPORTED_PROFILE_DATABASE" => "OUTSIDE_SUPPORTED_PROFILE_DATABASE",
        "OUTSIDE_SUPPORTED_PROFILE_OBJECTS" => "OUTSIDE_SUPPORTED_PROFILE_OBJECTS",
        "OUTSIDE_SUPPORTED_PROFILE_RECORDS" => "OUTSIDE_SUPPORTED_PROFILE_RECORDS",
        "CAPACITY_INSUFFICIENT" => "CAPACITY_INSUFFICIENT",
        "THROUGHPUT_EVIDENCE_REQUIRED" => "THROUGHPUT_EVIDENCE_REQUIRED",
        "DEADLINE_NOT_PLAUSIBLE" => "DEADLINE_NOT_PLAUSIBLE",
        _ => "RECOVERY_ADMISSION_REFUSED",
    }
}

/// `CheckBackupAdmission` — every C02 pre-mutation guard. Post-
/// acceptance write-quantum checks reuse it with a fresh snapshot.
///
/// Returns `Err(BackupCheck::Profile)` for an invalid profile
/// (upstream's plain `error`), and the typed `Diagnostic`/`Admission`
/// refusals otherwise.
pub fn check_backup_admission(
    profile: &RecoveryProfile,
    snapshot: &CapacitySnapshot,
) -> Result<(), BackupCheck> {
    if let Err(failure) = profile.validate() {
        return Err(BackupCheck::Profile(failure));
    }
    let refuse = |reason: &str| Err(BackupCheck::Admission(reason.to_owned()));
    if snapshot.database_bytes > profile.max_database_bytes {
        return Err(BackupCheck::Diagnostic(
            "OUTSIDE_SUPPORTED_PROFILE_DATABASE".to_owned(),
        ));
    }
    if snapshot.object_bytes > profile.max_object_bytes {
        return Err(BackupCheck::Diagnostic(
            "OUTSIDE_SUPPORTED_PROFILE_OBJECTS".to_owned(),
        ));
    }
    if snapshot.record_count > profile.max_record_count {
        return Err(BackupCheck::Diagnostic(
            "OUTSIDE_SUPPORTED_PROFILE_RECORDS".to_owned(),
        ));
    }
    if snapshot.sealed_backups >= profile.max_sealed_backups
        || snapshot.repository_bytes >= profile.max_repository_bytes
    {
        return refuse("CAPACITY_INSUFFICIENT");
    }
    if snapshot.devices.is_empty() {
        return refuse("CAPACITY_INSUFFICIENT");
    }
    // The repository receives a complete dump plus every live object
    // body; reserve that projected write before the survival reserve
    // and the free floor, and check every writable device
    // independently rather than aggregating free space.
    let Some(projected_write) = add_recovery_bytes(snapshot.database_bytes, snapshot.object_bytes)
    else {
        return refuse("CAPACITY_INSUFFICIENT");
    };
    // Upstream's subtraction is wrapping u64: a projected write beyond
    // the repository ceiling leaves the comparison unsatisfiable here
    // and the inflated threshold refuses every device below — the same
    // refusal, reached through the device check. `wrapping_sub`
    // reproduces that exactly.
    if snapshot.repository_bytes > profile.max_repository_bytes.wrapping_sub(projected_write) {
        return refuse("CAPACITY_INSUFFICIENT");
    }
    let Some(mut threshold) = add_recovery_bytes(profile.survival_reserve, profile.free_floor)
    else {
        return refuse("CAPACITY_INSUFFICIENT");
    };
    let Some(total) = add_recovery_bytes(threshold, projected_write) else {
        return refuse("CAPACITY_INSUFFICIENT");
    };
    threshold = total;
    let mut seen = std::collections::BTreeSet::new();
    for device in &snapshot.devices {
        if device.device_id.is_empty() || !seen.insert(device.device_id.as_str()) {
            return refuse("CAPACITY_INSUFFICIENT");
        }
        if device.free_bytes <= threshold {
            return refuse("CAPACITY_INSUFFICIENT");
        }
    }
    Ok(())
}

/// `addRecoveryBytes` — `None` on overflow.
pub(crate) fn add_recovery_bytes(left: u64, right: u64) -> Option<u64> {
    left.checked_add(right)
}

/// `multiplyRecoveryBytes` — `None` on overflow.
pub(crate) fn multiply_recovery_bytes(value: u64, factor: u64) -> Option<u64> {
    value.checked_mul(factor)
}

/// `BackupContinuitySnapshot` — the non-secret facts that must remain
/// true at every backup phase boundary, at most one write quantum
/// apart.
#[derive(Debug, Clone, Default)]
pub struct BackupContinuitySnapshot {
    /// Fresh capacity census.
    pub capacity: CapacitySnapshot,
    /// The accepted-point target lock still held.
    pub target_lock_held: bool,
    /// The authority receipt still held.
    pub authority_receipt_held: bool,
    /// Bytes written since the previous guard.
    pub bytes_since_last_guard: u64,
}

/// `CheckBackupContinuation` — C02's continuous guards after
/// admission. Every environmental loss maps to the resumable failure
/// class: ordinary backup cannot resume, but its evidence must
/// survive and the operator must see a deterministic safe failure.
pub fn check_backup_continuation(
    profile: &RecoveryProfile,
    operation: &BackupOperation,
    snapshot: &BackupContinuitySnapshot,
    now: time::OffsetDateTime,
) -> Result<(), Failure> {
    profile.validate()?;
    if operation.validate().is_err()
        || operation.phase == super::operation::BackupPhase::Planned
        || operation.phase.is_terminal()
        || crate::wire::is_zero_time(now)
        || now < operation.accepted_at
    {
        return Err(Failure::invalid(
            "backup_recovery",
            "invalid recovery backup continuation",
        ));
    }
    let resumable = |reason: &'static str| {
        Failure::new(
            FailureKind::Internal,
            reason,
            "preserve recovery evidence and create a new backup operation",
        )
    };
    if now - operation.accepted_at > profile.default_deadline {
        return Err(resumable("DEADLINE_EXCEEDED"));
    }
    if !snapshot.target_lock_held {
        return Err(resumable("TARGET_LOCK_LOST"));
    }
    if !snapshot.authority_receipt_held {
        return Err(resumable("AUTHORITY_LOST"));
    }
    if snapshot.bytes_since_last_guard > profile.write_quantum {
        return Err(resumable("WRITE_QUANTUM_EXCEEDED"));
    }
    if check_backup_admission(profile, &snapshot.capacity).is_err() {
        return Err(resumable("CAPACITY_OR_PROFILE_LOST"));
    }
    Ok(())
}

/// `RestoreCapacityDemand` — the canonical version-1 conservative
/// per-role restore plan in raw bytes. Carries no adapter-owned
/// request or role type so the backup adapter and the broker daemon's
/// admission gate share this exact arithmetic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RestoreCapacityDemand {
    /// PostgreSQL data-directory demand.
    pub postgres_data_bytes: u64,
    /// PostgreSQL WAL demand.
    pub postgres_wal_bytes: u64,
    /// PostgreSQL temp-directory demand.
    pub postgres_temp_bytes: u64,
    /// Object-store data-directory demand.
    pub object_data_bytes: u64,
}

/// `RoleRoots` — the resolved host directory backing each of the four
/// capacity-reserve roles. Carries no adapter-owned type so
/// `infralifecycle` (which resolves it) and the broker daemon (which
/// the future capacity gate reads it from) share the exact value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleRoots {
    /// PostgreSQL data root.
    pub postgres_data: String,
    /// PostgreSQL WAL root.
    pub postgres_wal: String,
    /// PostgreSQL temp root.
    pub postgres_temp: String,
    /// Object-store data root.
    pub object_data: String,
}

/// `RestoreCapacityDemands` — the archive size reserved independently
/// for PostgreSQL data and WAL; temp reserves another archive plus the
/// bounded inventory working set; object storage reserves every sealed
/// body byte. Overflow is a hard failure: returns `None`.
#[must_use]
pub fn restore_capacity_demands(
    dump_bytes: u64,
    object_bytes: u64,
    artifact_count: u64,
) -> Option<RestoreCapacityDemand> {
    let inventory_records = multiply_recovery_bytes(artifact_count, INVENTORY_RECORD_BOUND_BYTES)?;
    let chunks = artifact_count.div_ceil(MAXIMUM_INVENTORY_CHUNK_ENTRIES);
    let inventory_chunks = multiply_recovery_bytes(chunks, INVENTORY_CHUNK_BOUND_BYTES)?;
    let temp = add_recovery_bytes(dump_bytes, inventory_records)?;
    let temp = add_recovery_bytes(temp, inventory_chunks)?;
    let temp = add_recovery_bytes(temp, INVENTORY_FIXED_BOUND_BYTES)?;
    Some(RestoreCapacityDemand {
        postgres_data_bytes: dump_bytes,
        postgres_wal_bytes: dump_bytes,
        postgres_temp_bytes: temp,
        object_data_bytes: object_bytes,
    })
}

/// `RestoreAdmissionMargin` — `ceil(1.25 * planned)` without floating
/// point; `None` on overflow. The single source of the C03 per-device
/// admission margin.
#[must_use]
pub fn restore_admission_margin(planned: u64) -> Option<u64> {
    let quarter = planned.div_ceil(4);
    add_recovery_bytes(planned, quarter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::operation::BackupPhase;
    use crate::backup::operation::new_backup_operation;
    use crate::domain::TargetIdentity;
    use time::macros::datetime;

    fn admitted_snapshot() -> CapacitySnapshot {
        CapacitySnapshot {
            devices: vec![
                DeviceCapacitySnapshot {
                    device_id: "dev-a".into(),
                    free_bytes: 100 * GIBIBYTE,
                },
                DeviceCapacitySnapshot {
                    device_id: "dev-b".into(),
                    free_bytes: 100 * GIBIBYTE,
                },
            ],
            repository_bytes: 10 * GIBIBYTE,
            sealed_backups: 3,
            database_bytes: GIBIBYTE,
            object_bytes: 2 * GIBIBYTE,
            record_count: 100,
        }
    }

    #[test]
    fn profile_validate_bounds() {
        assert!(default_recovery_profile().validate().is_ok());
        let mut p = default_recovery_profile();
        p.max_database_bytes = 0;
        assert!(p.validate().is_err());
        p = default_recovery_profile();
        p.max_database_bytes = SUPPORTED_RECOVERY_DATABASE_BYTES + 1;
        assert!(p.validate().is_err());
        p = default_recovery_profile();
        p.min_throughput_bps = MINIMUM_RECOVERY_THROUGHPUT_BPS - 1;
        assert!(p.validate().is_err());
        p = default_recovery_profile();
        p.default_deadline = time::Duration::hours(9);
        assert!(p.validate().is_err());
        p = default_recovery_profile();
        p.throughput_max_age = THROUGHPUT_EVIDENCE_MAX_AGE + time::Duration::SECOND;
        assert!(p.validate().is_err());
    }

    #[test]
    fn admission_admits_measured_snapshot() {
        let profile = default_recovery_profile();
        assert!(check_backup_admission(&profile, &admitted_snapshot()).is_ok());
    }

    #[test]
    fn admission_refuses_each_guard() {
        let profile = default_recovery_profile();
        // Outside-profile diagnostics are the distinct class.
        for (field, want) in [
            ("database", "OUTSIDE_SUPPORTED_PROFILE_DATABASE"),
            ("objects", "OUTSIDE_SUPPORTED_PROFILE_OBJECTS"),
            ("records", "OUTSIDE_SUPPORTED_PROFILE_RECORDS"),
        ] {
            let mut snapshot = admitted_snapshot();
            match field {
                "database" => snapshot.database_bytes = profile.max_database_bytes + 1,
                "objects" => snapshot.object_bytes = profile.max_object_bytes + 1,
                _ => snapshot.record_count = profile.max_record_count + 1,
            }
            let verdict = check_backup_admission(&profile, &snapshot).unwrap_err();
            assert!(verdict.is_diagnostic_of(want), "{verdict:?}");
        }
        // Sealed-backup and repository ceilings.
        let mut snapshot = admitted_snapshot();
        snapshot.sealed_backups = profile.max_sealed_backups;
        let verdict = check_backup_admission(&profile, &snapshot).unwrap_err();
        assert!(verdict.is_admission("CAPACITY_INSUFFICIENT"));
        let mut snapshot = admitted_snapshot();
        snapshot.repository_bytes = profile.max_repository_bytes;
        assert!(
            check_backup_admission(&profile, &snapshot)
                .unwrap_err()
                .is_admission("CAPACITY_INSUFFICIENT")
        );
        // Empty device census.
        let mut snapshot = admitted_snapshot();
        snapshot.devices.clear();
        assert!(
            check_backup_admission(&profile, &snapshot)
                .unwrap_err()
                .is_admission("CAPACITY_INSUFFICIENT")
        );
        // Repository-byte reservation of the projected write.
        let mut snapshot = admitted_snapshot();
        snapshot.repository_bytes = profile.max_repository_bytes - 1;
        assert!(
            check_backup_admission(&profile, &snapshot)
                .unwrap_err()
                .is_admission("CAPACITY_INSUFFICIENT")
        );
        // Duplicate device identity.
        let mut snapshot = admitted_snapshot();
        snapshot.devices.push(snapshot.devices[0].clone());
        assert!(
            check_backup_admission(&profile, &snapshot)
                .unwrap_err()
                .is_admission("CAPACITY_INSUFFICIENT")
        );
        // Below the floor: reserve+floor+projected write.
        let mut snapshot = admitted_snapshot();
        let projected = snapshot.database_bytes + snapshot.object_bytes;
        let threshold = profile.survival_reserve + profile.free_floor + projected;
        snapshot.devices[0].free_bytes = threshold; // `<=` refuses exactly at the floor
        assert!(
            check_backup_admission(&profile, &snapshot)
                .unwrap_err()
                .is_admission("CAPACITY_INSUFFICIENT")
        );
        snapshot.devices[0].free_bytes = threshold + 1;
        assert!(check_backup_admission(&profile, &snapshot).is_ok());
    }

    #[test]
    fn capacity_floor_is_per_device_not_aggregated() {
        // Upstream CheckBackupAdmission checks every device
        // independently: two below-floor devices cannot pool.
        let profile = default_recovery_profile();
        let mut snapshot = admitted_snapshot();
        let projected = snapshot.database_bytes + snapshot.object_bytes;
        let threshold = profile.survival_reserve + profile.free_floor + projected;
        snapshot.devices = vec![
            DeviceCapacitySnapshot {
                device_id: "a".into(),
                free_bytes: threshold,
            },
            DeviceCapacitySnapshot {
                device_id: "b".into(),
                free_bytes: threshold,
            },
        ];
        assert!(
            check_backup_admission(&profile, &snapshot)
                .unwrap_err()
                .is_admission("CAPACITY_INSUFFICIENT")
        );
    }

    #[test]
    fn capacity_demands_and_margin() {
        let dump = 2 * GIBIBYTE;
        let objects = 3 * GIBIBYTE;
        let demand = restore_capacity_demands(dump, objects, 2_500).unwrap();
        assert_eq!(demand.postgres_data_bytes, dump);
        assert_eq!(demand.postgres_wal_bytes, dump);
        assert_eq!(demand.object_data_bytes, objects);
        // 2_500 records → 3 chunks; temp = dump + records + chunks + fixed.
        let records = 2_500 * INVENTORY_RECORD_BOUND_BYTES;
        let chunks = 3 * INVENTORY_CHUNK_BOUND_BYTES;
        assert_eq!(
            demand.postgres_temp_bytes,
            dump + records + chunks + INVENTORY_FIXED_BOUND_BYTES
        );
        assert_eq!(restore_admission_margin(100), Some(125));
        assert_eq!(restore_admission_margin(101), Some(127)); // ceil(1.25*101)=126.25→127? upstream: quarter=ceil(101/4)=26 → 127
        assert_eq!(restore_admission_margin(0), Some(0));
        assert_eq!(restore_admission_margin(u64::MAX), None);
        assert_eq!(restore_admission_margin(u64::MAX - 3), None);
    }

    fn admitted_operation(now: time::OffsetDateTime) -> BackupOperation {
        use crate::backup::operation::*;
        let facts = BackupAcceptedFacts {
            database_time: now,
            target_fingerprint: format!("sha256:{}", "a".repeat(64)),
            config_fingerprint: format!("sha256:{}", "b".repeat(64)),
            payload_epoch_id: uuid::Uuid::now_v7(),
            repository_binding_id: uuid::Uuid::now_v7(),
            target_lock_protocol: BACKUP_TARGET_LOCK_PROTOCOL.into(),
            target_lock_proof: format!("sha256:{}", "c".repeat(64)),
            inventory_boundary: BACKUP_INVENTORY_BOUNDARY.into(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            tool_version: BACKUP_DUMP_TOOL_VERSION.into(),
            checksum_manifest: BACKUP_CHECKSUM_MANIFEST.into(),
            service_identity: BACKUP_SERVICE_IDENTITY.into(),
        };
        let target = TargetIdentity {
            system_id: "sys".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        };
        let created = now - time::Duration::minutes(1);
        let op = new_backup_operation(uuid::Uuid::now_v7(), uuid::Uuid::now_v7(), target, created)
            .unwrap();
        op.accept(facts).unwrap()
    }

    #[test]
    fn continuation_guards() {
        let profile = default_recovery_profile();
        let now = datetime!(2026-03-01 12:00:00 UTC);
        let op = admitted_operation(now);
        let mut snapshot = BackupContinuitySnapshot {
            capacity: admitted_snapshot(),
            target_lock_held: true,
            authority_receipt_held: true,
            bytes_since_last_guard: 0,
        };
        assert!(check_backup_continuation(&profile, &op, &snapshot, now).is_ok());
        snapshot.bytes_since_last_guard = profile.write_quantum + 1;
        let err = check_backup_continuation(&profile, &op, &snapshot, now).unwrap_err();
        assert_eq!(err.code(), "WRITE_QUANTUM_EXCEEDED");
        snapshot.bytes_since_last_guard = 0;
        snapshot.target_lock_held = false;
        assert_eq!(
            check_backup_continuation(&profile, &op, &snapshot, now)
                .unwrap_err()
                .code(),
            "TARGET_LOCK_LOST"
        );
        snapshot.target_lock_held = true;
        snapshot.authority_receipt_held = false;
        assert_eq!(
            check_backup_continuation(&profile, &op, &snapshot, now)
                .unwrap_err()
                .code(),
            "AUTHORITY_LOST"
        );
        snapshot.authority_receipt_held = true;
        let late = op.accepted_at + profile.default_deadline + time::Duration::SECOND;
        assert_eq!(
            check_backup_continuation(&profile, &op, &snapshot, late)
                .unwrap_err()
                .code(),
            "DEADLINE_EXCEEDED"
        );
        snapshot.capacity.devices.clear();
        assert_eq!(
            check_backup_continuation(&profile, &op, &snapshot, now)
                .unwrap_err()
                .code(),
            "CAPACITY_OR_PROFILE_LOST"
        );
        // A planned operation is not a valid continuity subject.
        let planned = new_backup_operation(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            TargetIdentity {
                system_id: "s".into(),
                database_oid: "1".into(),
                database: "d".into(),
                config_hash: "c".into(),
                epoch: 0,
            },
            now,
        )
        .unwrap();
        assert!(planned.phase == BackupPhase::Planned);
        assert!(check_backup_continuation(&profile, &planned, &snapshot, now).is_err());
    }

    #[test]
    fn media_and_run_deadlines() {
        let p = default_recovery_profile();
        assert!(p.media_verification_deadline(0).is_none());
        let one = p.media_verification_deadline(1).unwrap();
        // media = 15 GiB, floor = 16 MiB/s → 960 s × 5/4 = 1200 s.
        assert_eq!(one, time::Duration::seconds(1200));
        // Two walks: 2400 s.
        assert_eq!(
            p.media_verification_deadline(2).unwrap(),
            time::Duration::seconds(2400)
        );
        assert_eq!(
            p.restore_run_deadline(time::Duration::minutes(2)).unwrap(),
            time::Duration::hours(2) + time::Duration::minutes(2)
        );
        assert!(p.restore_run_deadline(time::Duration::ZERO).is_none());
        let mut clamped = default_recovery_profile();
        clamped.default_deadline = time::Duration::hours(8);
        clamped.maximum_deadline = time::Duration::hours(8);
        assert_eq!(
            clamped
                .restore_run_deadline(time::Duration::minutes(30))
                .unwrap(),
            time::Duration::hours(8)
        );
    }
}
