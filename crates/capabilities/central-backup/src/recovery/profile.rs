//! `internal/backup/recovery.go` + `recovery/profile.go` — throughput
//! evidence, deadline plausibility, and the canonical restore capacity
//! plan. All admission refusals carry the `AdmissionFailure` reason
//! vocabulary ([`BackupCheck::Admission`]).

use time::Duration;
use uuid::Uuid;

use crate::backup::capacity::{
    BackupCheck, CapacitySnapshot, INVENTORY_CHUNK_BOUND_BYTES, INVENTORY_FIXED_BOUND_BYTES,
    INVENTORY_RECORD_BOUND_BYTES, MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES,
    MAXIMUM_INVENTORY_CHUNK_ENTRIES, MINIMUM_DUMP_ESTIMATE_BYTES, MINIMUM_DUMP_PROBE_ARCHIVE_BYTES,
    OBJECT_PROBE_PAYLOAD_BYTES, RecoveryProfile, add_recovery_bytes, multiply_recovery_bytes,
};
use crate::wire::{is_v7, is_zero_time, valid_sha256_fingerprint};

/// `BackupThroughputReceiptSchema`.
pub const BACKUP_THROUGHPUT_RECEIPT_SCHEMA: &str = "central.backup-throughput-receipt/v1";
/// `BackupThroughputCleanupClean` — the only cleanup state a receipt
/// may carry.
pub const BACKUP_THROUGHPUT_CLEANUP_CLEAN: &str = "clean";
/// `BackupTransferEnvelopeVersion`.
pub const BACKUP_TRANSFER_ENVELOPE_VERSION: &str = "central.backup-transfer-envelope/v1";
/// `MaximumThroughputProbeElapsed` — 5 minutes (re-exported alias of
/// [`crate::backup::capacity::MAXIMUM_THROUGHPUT_PROBE_ELAPSED`]).
pub use crate::backup::capacity::MAXIMUM_THROUGHPUT_PROBE_ELAPSED;

fn admission(reason: &str) -> BackupCheck {
    BackupCheck::Admission(reason.to_owned())
}

/// `ThroughputEvidenceBinding` — the complete current, locator-free
/// environment identity a receipt must match. Derived by trusted
/// infrastructure adapters; a caller cannot select any field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThroughputEvidenceBinding {
    /// Instance identity (v7).
    pub instance_id: Uuid,
    /// Payload epoch (v7).
    pub payload_epoch_id: Uuid,
    /// `sha256:`-prefixed target fingerprint.
    pub target_fingerprint: String,
    /// Repository binding identity.
    pub repository_binding_id: Uuid,
    /// `sha256:`-prefixed device-mount-set digest.
    pub device_mount_set_digest: String,
    /// `sha256:`-prefixed host profile digest.
    pub host_profile_digest: String,
    /// `sha256:`-prefixed dependency provisioning digest.
    pub dependency_provisioning_digest: String,
    /// `sha256:`-prefixed postgres image digest.
    pub postgres_image_digest: String,
    /// `sha256:`-prefixed minio image digest.
    pub minio_image_digest: String,
    /// `sha256:`-prefixed pg_dump tool digest.
    pub pg_dump_tool_digest: String,
    /// Pinned `"16.14"`.
    pub pg_dump_tool_version: String,
    /// `sha256:`-prefixed config digest (of `PinnedBackupConfiguration`).
    pub config_digest: String,
    /// `sha256:`-prefixed MinIO backup policy digest.
    pub minio_backup_policy_digest: String,
    /// `sha256:`-prefixed fixture digest.
    pub fixture_digest: String,
    /// Fixed [`BACKUP_TRANSFER_ENVELOPE_VERSION`].
    pub transfer_envelope_version: String,
    /// `sha256:`-prefixed transfer envelope digest.
    pub transfer_envelope_digest: String,
}

impl ThroughputEvidenceBinding {
    /// `Validate` — refuses as `THROUGHPUT_EVIDENCE_REQUIRED`.
    pub fn validate(&self) -> Result<(), BackupCheck> {
        if !is_v7(self.instance_id)
            || !is_v7(self.payload_epoch_id)
            || !valid_sha256_fingerprint(&self.target_fingerprint)
            || self.repository_binding_id.is_nil()
            || !valid_sha256_fingerprint(&self.device_mount_set_digest)
            || !valid_sha256_fingerprint(&self.host_profile_digest)
            || !valid_sha256_fingerprint(&self.dependency_provisioning_digest)
            || !valid_sha256_fingerprint(&self.postgres_image_digest)
            || !valid_sha256_fingerprint(&self.minio_image_digest)
            || !valid_sha256_fingerprint(&self.pg_dump_tool_digest)
            || self.pg_dump_tool_version != "16.14"
            || !valid_sha256_fingerprint(&self.config_digest)
            || !valid_sha256_fingerprint(&self.minio_backup_policy_digest)
            || !valid_sha256_fingerprint(&self.fixture_digest)
            || self.transfer_envelope_version != BACKUP_TRANSFER_ENVELOPE_VERSION
            || !valid_sha256_fingerprint(&self.transfer_envelope_digest)
        {
            return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
        }
        Ok(())
    }
}

/// `ThroughputEvidence` — the bounded probe receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThroughputEvidence {
    /// Fixed [`BACKUP_THROUGHPUT_RECEIPT_SCHEMA`].
    pub schema_version: String,
    /// Receipt identity.
    pub receipt_id: Uuid,
    /// Probe operation identity.
    pub probe_operation_id: Uuid,
    /// Probe start.
    pub probe_started_at: time::OffsetDateTime,
    /// Probe completion.
    pub probe_completed_at: time::OffsetDateTime,
    /// Probe wall-clock elapsed.
    pub probe_elapsed: Duration,
    /// Measurement instant (must equal `probe_completed_at`).
    pub measured_at: time::OffsetDateTime,
    /// Expiry instant.
    pub expires_at: time::OffsetDateTime,
    /// The bound environment identity, flattened.
    pub binding: ThroughputEvidenceBinding,
    /// Dump archive bytes.
    pub dump_archive_bytes: u64,
    /// Dump work bytes (must equal `2 × archive`).
    pub dump_work_bytes: u64,
    /// Dump elapsed.
    pub dump_elapsed: Duration,
    /// Fixture load elapsed.
    pub fixture_load_elapsed: Duration,
    /// Derived dump bytes/second.
    pub dump_bytes_per_sec: u64,
    /// Object payload bytes (must equal [`OBJECT_PROBE_PAYLOAD_BYTES`]).
    pub object_payload_bytes: u64,
    /// Object work bytes (must equal `3 × payload`).
    pub object_work_bytes: u64,
    /// Object elapsed.
    pub object_elapsed: Duration,
    /// Derived object bytes/second.
    pub object_bytes_per_sec: u64,
    /// Fixed `"clean"`.
    pub cleanup_state: String,
    /// Cleanup verification instant (must equal `probe_completed_at`).
    pub cleanup_verified_at: time::OffsetDateTime,
}

impl ThroughputEvidence {
    /// `Binding`.
    #[must_use]
    pub fn binding(&self) -> &ThroughputEvidenceBinding {
        &self.binding
    }

    /// `ValidFor` — freshness and raw measurement over the exact
    /// current environment. A valid receipt from another instance,
    /// payload epoch, repository, device set, tool, image, policy, or
    /// transfer envelope is historical evidence only.
    pub fn valid_for(
        &self,
        now: time::OffsetDateTime,
        profile: &RecoveryProfile,
        expected: &ThroughputEvidenceBinding,
    ) -> Result<(), BackupCheck> {
        expected.validate()?;
        self.valid_at(now, profile)?;
        if &self.binding != expected {
            return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
        }
        Ok(())
    }

    /// `ValidAt` — verifies both required paths and rejects stale or
    /// future evidence.
    pub fn valid_at(
        &self,
        now: time::OffsetDateTime,
        profile: &RecoveryProfile,
    ) -> Result<(), BackupCheck> {
        if let Err(failure) = profile.validate() {
            return Err(BackupCheck::Profile(failure));
        }
        if self.schema_version != BACKUP_THROUGHPUT_RECEIPT_SCHEMA
            || self.receipt_id.is_nil()
            || self.probe_operation_id.is_nil()
            || is_zero_time(self.probe_started_at)
            || is_zero_time(self.probe_completed_at)
            || self.probe_started_at >= self.probe_completed_at
            || self.probe_elapsed <= Duration::ZERO
            || self.probe_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || self.measured_at != self.probe_completed_at
            || is_zero_time(self.measured_at)
            || is_zero_time(self.expires_at)
            || self.measured_at > now
            || now >= self.expires_at
            || self.expires_at > self.measured_at + profile.throughput_max_age
            || self.binding.validate().is_err()
            || self.cleanup_state != BACKUP_THROUGHPUT_CLEANUP_CLEAN
            || is_zero_time(self.cleanup_verified_at)
            || self.cleanup_verified_at != self.probe_completed_at
            || self.cleanup_verified_at > now
        {
            return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
        }
        if self.dump_archive_bytes < MINIMUM_DUMP_PROBE_ARCHIVE_BYTES
            || self.dump_archive_bytes > MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES
            || self.dump_work_bytes != self.dump_archive_bytes * 2
            || self.object_payload_bytes != OBJECT_PROBE_PAYLOAD_BYTES
            || self.object_work_bytes != self.object_payload_bytes * 3
            || self.fixture_load_elapsed <= Duration::ZERO
            || self.dump_elapsed <= Duration::ZERO
            || self.dump_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || self.object_elapsed <= Duration::ZERO
            || self.object_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || self.fixture_load_elapsed > self.probe_elapsed
            || self.dump_elapsed > self.probe_elapsed - self.fixture_load_elapsed
            || self.object_elapsed
                > self.probe_elapsed - self.fixture_load_elapsed - self.dump_elapsed
        {
            return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
        }
        let Some(dump_rate) = measured_bytes_per_second(self.dump_work_bytes, self.dump_elapsed)
        else {
            return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
        };
        let Some(object_rate) =
            measured_bytes_per_second(self.object_work_bytes, self.object_elapsed)
        else {
            return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
        };
        if self.dump_bytes_per_sec != dump_rate
            || self.object_bytes_per_sec != object_rate
            || dump_rate < profile.min_throughput_bps
            || object_rate < profile.min_throughput_bps
        {
            return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
        }
        Ok(())
    }
}

/// `measuredBytesPerSecond` — `None` on zero/degenerate inputs or
/// overflow.
fn measured_bytes_per_second(bytes: u64, elapsed: Duration) -> Option<u64> {
    if bytes == 0 || elapsed <= Duration::ZERO {
        return None;
    }
    bytes
        .checked_mul(Duration::SECOND.whole_nanoseconds() as u64)?
        .checked_div(elapsed.whole_nanoseconds() as u64)
}

/// `recoveryStageSeconds` — ceiling division.
fn recovery_stage_seconds(work_bytes: u64, rate: u64) -> u64 {
    if work_bytes == 0 {
        return 0;
    }
    work_bytes / rate + u64::from(!work_bytes.is_multiple_of(rate))
}

/// `CheckBackupDeadlinePlausibility` — the slower measured path and
/// the full projected work: every database byte published and
/// synchronously reread (×2), every object byte read, written, and
/// synchronously reread (×3), bounded inventory work. Admission
/// consumes at most 75% of the fixed parent deadline, reserving the
/// remaining quarter for lock acquisition, retries, and variance.
pub fn check_backup_deadline_plausibility(
    profile: &RecoveryProfile,
    snapshot: &CapacitySnapshot,
    evidence: &ThroughputEvidence,
) -> Result<(), BackupCheck> {
    if let Err(failure) = profile.validate() {
        return Err(BackupCheck::Profile(failure));
    }
    if evidence.dump_bytes_per_sec == 0 || evidence.object_bytes_per_sec == 0 {
        return Err(admission("THROUGHPUT_EVIDENCE_REQUIRED"));
    }
    let dump_estimate = snapshot.database_bytes.max(MINIMUM_DUMP_ESTIMATE_BYTES);
    let Some(dump_work) = multiply_recovery_bytes(dump_estimate, 2) else {
        return Err(admission("DEADLINE_NOT_PLAUSIBLE"));
    };
    let Some(object_work) = multiply_recovery_bytes(snapshot.object_bytes, 3) else {
        return Err(admission("DEADLINE_NOT_PLAUSIBLE"));
    };
    let Some(inventory_records) =
        multiply_recovery_bytes(snapshot.record_count, INVENTORY_RECORD_BOUND_BYTES)
    else {
        return Err(admission("DEADLINE_NOT_PLAUSIBLE"));
    };
    let chunks = snapshot.record_count / MAXIMUM_INVENTORY_CHUNK_ENTRIES
        + u64::from(
            !snapshot
                .record_count
                .is_multiple_of(MAXIMUM_INVENTORY_CHUNK_ENTRIES),
        );
    let Some(inventory_chunks) = multiply_recovery_bytes(chunks, INVENTORY_CHUNK_BOUND_BYTES)
    else {
        return Err(admission("DEADLINE_NOT_PLAUSIBLE"));
    };
    let Some(inventory_work) = add_recovery_bytes(inventory_records, inventory_chunks)
        .and_then(|v| add_recovery_bytes(v, INVENTORY_FIXED_BOUND_BYTES))
    else {
        return Err(admission("DEADLINE_NOT_PLAUSIBLE"));
    };
    let slower_rate = evidence
        .dump_bytes_per_sec
        .min(evidence.object_bytes_per_sec);
    let Some(total_work) = add_recovery_bytes(dump_work, object_work)
        .and_then(|v| add_recovery_bytes(v, inventory_work))
    else {
        return Err(admission("DEADLINE_NOT_PLAUSIBLE"));
    };
    let seconds = recovery_stage_seconds(total_work, slower_rate);
    let budget: Duration = profile.default_deadline * 3 / 4;
    if seconds > budget.whole_seconds().max(0) as u64 {
        return Err(admission("DEADLINE_NOT_PLAUSIBLE"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::capacity::{
        CapacitySnapshot, DeviceCapacitySnapshot, default_recovery_profile,
        restore_admission_margin, restore_capacity_demands,
    };
    use time::macros::datetime;

    fn digest(ch: &str) -> String {
        format!("sha256:{}", ch.repeat(64))
    }

    fn binding() -> ThroughputEvidenceBinding {
        ThroughputEvidenceBinding {
            instance_id: Uuid::now_v7(),
            payload_epoch_id: Uuid::now_v7(),
            target_fingerprint: digest("a"),
            repository_binding_id: Uuid::now_v7(),
            device_mount_set_digest: digest("1"),
            host_profile_digest: digest("2"),
            dependency_provisioning_digest: digest("3"),
            postgres_image_digest: digest("4"),
            minio_image_digest: digest("5"),
            pg_dump_tool_digest: digest("6"),
            pg_dump_tool_version: "16.14".into(),
            config_digest: digest("7"),
            minio_backup_policy_digest: digest("8"),
            fixture_digest: digest("9"),
            transfer_envelope_version: BACKUP_TRANSFER_ENVELOPE_VERSION.into(),
            transfer_envelope_digest: digest("0"),
        }
    }

    fn evidence() -> ThroughputEvidence {
        let completed = datetime!(2026-03-01 12:00:00 UTC);
        // dump: 512 MiB archive, 1 GiB work over 60 s → ~17.9 MiB/s.
        let archive = MINIMUM_DUMP_PROBE_ARCHIVE_BYTES;
        ThroughputEvidence {
            schema_version: BACKUP_THROUGHPUT_RECEIPT_SCHEMA.into(),
            receipt_id: Uuid::now_v7(),
            probe_operation_id: Uuid::now_v7(),
            probe_started_at: completed - Duration::seconds(200),
            probe_completed_at: completed,
            probe_elapsed: Duration::seconds(200),
            measured_at: completed,
            expires_at: completed + Duration::days(7),
            binding: binding(),
            dump_archive_bytes: archive,
            dump_work_bytes: archive * 2,
            dump_elapsed: Duration::seconds(60),
            fixture_load_elapsed: Duration::seconds(10),
            dump_bytes_per_sec: measured_bytes_per_second(archive * 2, Duration::seconds(60))
                .unwrap(),
            object_payload_bytes: OBJECT_PROBE_PAYLOAD_BYTES,
            object_work_bytes: OBJECT_PROBE_PAYLOAD_BYTES * 3,
            object_elapsed: Duration::seconds(60),
            object_bytes_per_sec: measured_bytes_per_second(
                OBJECT_PROBE_PAYLOAD_BYTES * 3,
                Duration::seconds(60),
            )
            .unwrap(),
            cleanup_state: BACKUP_THROUGHPUT_CLEANUP_CLEAN.into(),
            cleanup_verified_at: completed,
        }
    }

    #[test]
    fn throughput_evidence_validates_fresh_bound_measurement() {
        let profile = default_recovery_profile();
        let evidence = evidence();
        let now = datetime!(2026-03-01 12:05:00 UTC);
        assert!(evidence.valid_at(now, &profile).is_ok());
        assert!(
            evidence
                .valid_for(now, &profile, &evidence.binding.clone())
                .is_ok()
        );
        // A receipt from another environment is historical only.
        let mut expected = evidence.binding.clone();
        expected.fixture_digest = digest("e");
        assert!(evidence.valid_for(now, &profile, &expected).is_err());
        // Stale and future receipts refuse.
        let mut stale = evidence.clone();
        stale.expires_at = now - Duration::SECOND;
        assert!(stale.valid_at(now, &profile).is_err());
        let mut future = evidence.clone();
        future.measured_at = now + Duration::HOUR;
        assert!(future.valid_at(now, &profile).is_err());
        // Lying rates refuse: recompute must match.
        let mut lying = evidence.clone();
        lying.dump_bytes_per_sec += 1;
        assert!(lying.valid_at(now, &profile).is_err());
        // Below-floor rates refuse.
        let mut slow = evidence.clone();
        slow.dump_elapsed = Duration::seconds(299);
        let rate = measured_bytes_per_second(slow.dump_work_bytes, slow.dump_elapsed);
        slow.dump_bytes_per_sec = rate.unwrap_or(0);
        assert!(slow.valid_at(now, &profile).is_err());
        // Wrong tool version in the binding refuses.
        let mut tool = evidence.clone();
        tool.binding.pg_dump_tool_version = "15.9".into();
        assert!(tool.valid_at(now, &profile).is_err());
        // Dirty cleanup refuses.
        let mut dirty = evidence;
        dirty.cleanup_state = "residual".into();
        assert!(dirty.valid_at(now, &profile).is_err());
    }

    #[test]
    fn deadline_plausibility_uses_slower_path_and_75_percent() {
        let profile = default_recovery_profile();
        let snapshot = CapacitySnapshot {
            devices: vec![DeviceCapacitySnapshot {
                device_id: "d0".into(),
                free_bytes: u64::MAX / 2,
            }],
            database_bytes: MINIMUM_DUMP_ESTIMATE_BYTES,
            object_bytes: 0,
            record_count: 0,
            ..Default::default()
        };
        let mut ev = evidence();
        // 2 GiB work at 16 MiB/s ≈ 128 s < 90 min budget → plausible.
        assert!(check_backup_deadline_plausibility(&profile, &snapshot, &ev).is_ok());
        // An enormous database makes the deadline implausible.
        let mut big = snapshot.clone();
        big.database_bytes = 4 * 1024 * 1024 * 1024 * 1024; // 4 TiB
        ev.dump_bytes_per_sec = profile.min_throughput_bps;
        ev.object_bytes_per_sec = profile.min_throughput_bps;
        assert!(
            check_backup_deadline_plausibility(&profile, &big, &ev)
                .unwrap_err()
                .is_admission("DEADLINE_NOT_PLAUSIBLE")
        );
        // Zero-rate evidence is throughput-evidence refusal, not deadline.
        let mut zero = evidence();
        zero.dump_bytes_per_sec = 0;
        zero.object_bytes_per_sec = 0;
        assert!(
            check_backup_deadline_plausibility(&profile, &snapshot, &zero)
                .unwrap_err()
                .is_admission("THROUGHPUT_EVIDENCE_REQUIRED")
        );
    }

    #[test]
    fn capacity_demands_and_margin() {
        let demands = restore_capacity_demands(1 << 30, 2 << 30, 10_000).unwrap();
        assert_eq!(demands.postgres_data_bytes, 1 << 30);
        assert_eq!(demands.postgres_wal_bytes, 1 << 30);
        assert!(demands.postgres_temp_bytes > 1 << 30);
        assert_eq!(demands.object_data_bytes, 2 << 30);
        assert_eq!(restore_admission_margin(100), Some(125));
        assert_eq!(restore_admission_margin(101), Some(127)); // ceil
        assert_eq!(restore_admission_margin(0), Some(0));
        assert!(restore_admission_margin(u64::MAX).is_none());
        assert!(restore_capacity_demands(u64::MAX, 0, 0).is_none());
    }

    #[test]
    fn derived_deadlines() {
        let profile = default_recovery_profile();
        // ~15 GiB at 16 MiB/s = 960 s → margin 1200 s for 1 walk.
        let deadline = profile.media_verification_deadline(1).unwrap();
        assert_eq!(deadline, Duration::seconds(1200));
        assert_eq!(profile.media_verification_deadline(0), None);
        // Many walks clamp to the maximum.
        assert_eq!(
            profile.media_verification_deadline(1_000),
            Some(profile.maximum_deadline)
        );
        // Ceremony is added, clamped at the maximum.
        assert_eq!(
            profile.restore_run_deadline(Duration::minutes(2)),
            Some(Duration::hours(2) + Duration::minutes(2))
        );
        assert_eq!(
            profile.restore_run_deadline(Duration::hours(20)),
            Some(profile.maximum_deadline)
        );
        assert_eq!(profile.restore_run_deadline(Duration::ZERO), None);
    }
}
