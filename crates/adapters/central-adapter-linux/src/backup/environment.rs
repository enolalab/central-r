//! `environment.go` — [`BackupEnvironment`] aggregates independently
//! trusted C02 measurements. It does not mint authority, throughput
//! evidence, accepted facts, or paths; all six capabilities are
//! required and supplied by the helper-launched composition.
//!
//! Every snapshot boundary re-reads each capability so a stale
//! observation can never be admitted; repository bytes may only grow
//! between continuation guards.

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use central_backup::backup::capacity::{
    BackupContinuitySnapshot, CapacitySnapshot, DeviceCapacitySnapshot,
};
use central_backup::backup::operation::{BackupOperation, BackupPhase};
use central_backup::port::{
    BackupAcceptedFactsBuilder, BackupAdmissionSnapshot, BackupAuthorityLease,
    BackupDatabaseCensus, BackupDatabaseCensusReader, BackupEnvironmentProbe,
    BackupRepositoryCensus, BackupRepositoryInspector, BackupTargetExclusion,
    BackupThroughputSource,
};
use central_foundation::failure::Failure;
use uuid::Uuid;

/// `wire.zero_time` — the domain's Go `time.Time{}` equivalent.
pub(crate) fn zero_time() -> time::OffsetDateTime {
    time::OffsetDateTime::UNIX_EPOCH
        .replace_year(1)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// `time.Time.IsZero` — the same convention the domain's wire layer
/// pins (year 1, January 1, UTC).
pub(crate) fn is_zero_time(t: time::OffsetDateTime) -> bool {
    t.year() == 1
        && t.month() == time::Month::January
        && t.day() == 1
        && t.hour() == 0
        && t.minute() == 0
        && t.second() == 0
        && t.nanosecond() == 0
}

/// `ErrBackupEnvironment` — the closed, locator-free environment
/// refusal. Upstream is a plain sentinel; the capability boundary
/// fails closed on it.
fn environment_unavailable() -> Failure {
    Failure::unavailable(
        "backup_environment",
        "recovery backup environment is unavailable",
    )
}

/// One held-lever capability set plus the admitted-guard state. The
/// mutex upstream holds across a whole snapshot keeps the two guard
/// transitions (admission, each continuation) serial.
struct EnvironmentState {
    operation_id: Uuid,
    last_repository_bytes: u64,
    admitted: bool,
}

/// `BackupEnvironment` — see the module header.
pub struct BackupEnvironment {
    lock: Arc<dyn BackupTargetExclusion>,
    repository: Arc<dyn BackupRepositoryInspector>,
    database: Arc<dyn BackupDatabaseCensusReader>,
    authority: Arc<dyn BackupAuthorityLease>,
    throughput: Arc<dyn BackupThroughputSource>,
    facts: Arc<dyn BackupAcceptedFactsBuilder>,
    state: Mutex<EnvironmentState>,
}

/// `NewBackupEnvironment` — every capability must be present; a
/// missing one is an environment failure, exactly like upstream's nil
/// check.
#[allow(clippy::too_many_arguments)]
pub fn new_backup_environment(
    lock: Option<Arc<dyn BackupTargetExclusion>>,
    repository: Option<Arc<dyn BackupRepositoryInspector>>,
    database: Option<Arc<dyn BackupDatabaseCensusReader>>,
    authority: Option<Arc<dyn BackupAuthorityLease>>,
    throughput: Option<Arc<dyn BackupThroughputSource>>,
    facts: Option<Arc<dyn BackupAcceptedFactsBuilder>>,
) -> Result<BackupEnvironment, Failure> {
    let (
        Some(lock),
        Some(repository),
        Some(database),
        Some(authority),
        Some(throughput),
        Some(facts),
    ) = (lock, repository, database, authority, throughput, facts)
    else {
        return Err(environment_unavailable());
    };
    Ok(BackupEnvironment {
        lock,
        repository,
        database,
        authority,
        throughput,
        facts,
        state: Mutex::new(EnvironmentState {
            operation_id: Uuid::nil(),
            last_repository_bytes: 0,
            admitted: false,
        }),
    })
}

impl BackupEnvironment {
    /// `capacity` — the three independent trusted measurements that
    /// every snapshot boundary must observe fresh.
    fn capacity(
        &self,
    ) -> Result<
        (
            BackupDatabaseCensus,
            BackupRepositoryCensus,
            DeviceCapacitySnapshot,
        ),
        Failure,
    > {
        let database = self.database.read_backup_capacity()?;
        if is_zero_time(database.database_time) {
            return Err(environment_unavailable());
        }
        let repository = self.repository.capacity_census()?;
        let device = self.repository.device_capacity()?;
        if device.device_id.is_empty() {
            return Err(environment_unavailable());
        }
        Ok((database, repository, device))
    }

    fn capacity_snapshot(
        database: &BackupDatabaseCensus,
        repository: &BackupRepositoryCensus,
        device: DeviceCapacitySnapshot,
    ) -> CapacitySnapshot {
        CapacitySnapshot {
            devices: vec![device],
            repository_bytes: repository.bytes,
            sealed_backups: repository.sealed_backups,
            database_bytes: database.database_bytes,
            object_bytes: database.object_bytes,
            record_count: database.record_count,
        }
    }
}

impl BackupEnvironmentProbe for BackupEnvironment {
    /// `AdmissionSnapshot` — validates the planned operation, asserts
    /// the target lock and authority receipt, takes the fresh capacity
    /// triple, builds facts from that same database timestamp and
    /// repository binding, reads the bound throughput evidence, then
    /// records the operation and its repository byte baseline.
    fn admission_snapshot(
        &self,
        operation: &BackupOperation,
    ) -> Result<BackupAdmissionSnapshot, Failure> {
        if operation.validate().is_err() || operation.phase != BackupPhase::Planned {
            return Err(environment_unavailable());
        }
        let mut state = self.state.lock().map_err(|_| environment_unavailable())?;
        if state.admitted {
            return Err(environment_unavailable());
        }
        let lock_held = self.lock.assert_held().is_ok();
        let authority_held = self.authority.assert_held().is_ok();
        let (database, repository, device) = self.capacity()?;
        let binding_id = self.repository.binding_id();
        let facts = self
            .facts
            .build_backup_accepted_facts(
                operation,
                database.database_time,
                binding_id,
                &self.lock.proof(),
            )
            .map_err(|_| environment_unavailable())?;
        if facts.validate().is_err()
            || facts.repository_binding_id != binding_id
            || facts.database_time != database.database_time
            || facts.target_lock_proof != self.lock.proof()
        {
            return Err(environment_unavailable());
        }
        let throughput = self
            .throughput
            .read_backup_throughput(operation, &facts)
            .map_err(|_| environment_unavailable())?;
        state.operation_id = operation.operation_id;
        state.last_repository_bytes = repository.bytes;
        state.admitted = true;
        Ok(BackupAdmissionSnapshot {
            facts,
            capacity: Self::capacity_snapshot(&database, &repository, device),
            throughput,
            target_lock_held: lock_held,
            authority_receipt_held: authority_held,
        })
    }

    /// `ContinuationSnapshot` — only the admitted operation, never a
    /// planned or terminal one; re-asserts the lock and authority,
    /// re-reads the capacities, rejects a repository byte decrease,
    /// and reports the bytes written since the previous guard.
    fn continuation_snapshot(
        &self,
        operation: &BackupOperation,
    ) -> Result<BackupContinuitySnapshot, Failure> {
        if operation.validate().is_err()
            || operation.phase == BackupPhase::Planned
            || operation.phase.is_terminal()
        {
            return Err(environment_unavailable());
        }
        let mut state = self.state.lock().map_err(|_| environment_unavailable())?;
        if !state.admitted || state.operation_id != operation.operation_id {
            return Err(environment_unavailable());
        }
        let lock_held = self.lock.assert_held().is_ok();
        let authority_held = self.authority.assert_held().is_ok();
        let (database, repository, device) = self.capacity()?;
        if repository.bytes < state.last_repository_bytes {
            return Err(environment_unavailable());
        }
        let bytes_since_last_guard = repository.bytes - state.last_repository_bytes;
        state.last_repository_bytes = repository.bytes;
        Ok(BackupContinuitySnapshot {
            capacity: Self::capacity_snapshot(&database, &repository, device),
            target_lock_held: lock_held,
            authority_receipt_held: authority_held,
            bytes_since_last_guard,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_backup::backup::operation::{
        BackupAcceptedFacts, new_backup_accepted_facts, new_backup_operation,
    };
    use central_backup::domain::TargetIdentity;
    use central_backup::recovery::profile::{
        BACKUP_THROUGHPUT_RECEIPT_SCHEMA, ThroughputEvidence, ThroughputEvidenceBinding,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    const PROOF: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const TARGET_FP: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const CONFIG_FP: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    struct FakeLock {
        held: Arc<AtomicBool>,
    }
    impl BackupTargetExclusion for FakeLock {
        fn assert_held(&self) -> Result<(), Failure> {
            if self.held.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(Failure::unavailable("test_lock", "lock lost"))
            }
        }
        fn release(&self) -> Result<(), Failure> {
            Ok(())
        }
        fn proof(&self) -> String {
            PROOF.to_owned()
        }
        fn client_port(&self) -> Option<u16> {
            None
        }
        fn mark_retained(&self) -> Result<(), Failure> {
            Err(Failure::unavailable("test_lock", "retention unsupported"))
        }
    }

    struct FakeInspector {
        bytes: Arc<AtomicU64>,
        sealed: u64,
        binding_id: Uuid,
        device_id: String,
    }
    impl BackupRepositoryInspector for FakeInspector {
        fn capacity_census(&self) -> Result<BackupRepositoryCensus, Failure> {
            Ok(BackupRepositoryCensus {
                bytes: self.bytes.load(Ordering::SeqCst),
                sealed_backups: self.sealed,
            })
        }
        fn device_capacity(&self) -> Result<DeviceCapacitySnapshot, Failure> {
            Ok(DeviceCapacitySnapshot {
                device_id: self.device_id.clone(),
                free_bytes: 1 << 40,
            })
        }
        fn binding_id(&self) -> Uuid {
            self.binding_id
        }
    }

    struct FakeDatabase;
    impl BackupDatabaseCensusReader for FakeDatabase {
        fn read_backup_capacity(&self) -> Result<BackupDatabaseCensus, Failure> {
            Ok(BackupDatabaseCensus {
                database_time: time::OffsetDateTime::now_utc(),
                database_bytes: 1 << 20,
                object_bytes: 1 << 30,
                record_count: 7,
            })
        }
    }

    struct FakeAuthority {
        held: Arc<AtomicBool>,
    }
    impl BackupAuthorityLease for FakeAuthority {
        fn assert_held(&self) -> Result<(), Failure> {
            if self.held.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(Failure::unavailable("test_authority", "authority lost"))
            }
        }
    }

    struct FakeThroughput {
        evidence: ThroughputEvidence,
    }
    impl BackupThroughputSource for FakeThroughput {
        fn read_backup_throughput(
            &self,
            _operation: &BackupOperation,
            _facts: &BackupAcceptedFacts,
        ) -> Result<ThroughputEvidence, Failure> {
            Ok(self.evidence.clone())
        }
    }

    struct FakeFacts;
    impl BackupAcceptedFactsBuilder for FakeFacts {
        fn build_backup_accepted_facts(
            &self,
            _operation: &BackupOperation,
            database_time: time::OffsetDateTime,
            repository_binding_id: Uuid,
            target_lock_proof: &str,
        ) -> Result<BackupAcceptedFacts, Failure> {
            new_backup_accepted_facts(
                database_time,
                TARGET_FP,
                CONFIG_FP,
                Uuid::now_v7(),
                repository_binding_id,
                target_lock_proof,
            )
        }
    }

    fn evidence() -> ThroughputEvidence {
        let fingerprint = |byte: u8| format!("sha256:{}", format!("{byte:02x}").repeat(32));
        let now = time::OffsetDateTime::now_utc();
        ThroughputEvidence {
            schema_version: BACKUP_THROUGHPUT_RECEIPT_SCHEMA.into(),
            receipt_id: Uuid::now_v7(),
            probe_operation_id: Uuid::now_v7(),
            probe_started_at: now,
            probe_completed_at: now,
            probe_elapsed: time::Duration::seconds(30),
            measured_at: now,
            expires_at: now + time::Duration::hours(1),
            binding: ThroughputEvidenceBinding {
                instance_id: Uuid::now_v7(),
                payload_epoch_id: Uuid::now_v7(),
                target_fingerprint: fingerprint(0x11),
                repository_binding_id: Uuid::now_v7(),
                device_mount_set_digest: fingerprint(0x22),
                host_profile_digest: fingerprint(0x23),
                dependency_provisioning_digest: fingerprint(0x24),
                postgres_image_digest: fingerprint(0x25),
                minio_image_digest: fingerprint(0x26),
                pg_dump_tool_digest: fingerprint(0x27),
                pg_dump_tool_version: "16.14".into(),
                config_digest: fingerprint(0x28),
                minio_backup_policy_digest: fingerprint(0x29),
                fixture_digest: fingerprint(0x2a),
                transfer_envelope_version: "central.backup-transfer-envelope/v1".into(),
                transfer_envelope_digest: fingerprint(0x2b),
            },
            dump_archive_bytes: 1024,
            dump_work_bytes: 2048,
            dump_elapsed: time::Duration::seconds(2),
            fixture_load_elapsed: time::Duration::seconds(1),
            dump_bytes_per_sec: 512,
            object_payload_bytes: 4096,
            object_work_bytes: 3 * 4096,
            object_elapsed: time::Duration::seconds(2),
            object_bytes_per_sec: 2048,
            cleanup_state: "clean".into(),
            cleanup_verified_at: now,
        }
    }

    struct Harness {
        environment: BackupEnvironment,
        binding_id: Uuid,
        repo_bytes: Arc<AtomicU64>,
        lock_held: Arc<AtomicBool>,
        authority_held: Arc<AtomicBool>,
    }

    fn harness() -> Harness {
        let binding_id = Uuid::now_v7();
        let repo_bytes = Arc::new(AtomicU64::new(4096));
        let lock_held = Arc::new(AtomicBool::new(true));
        let authority_held = Arc::new(AtomicBool::new(true));
        let environment = new_backup_environment(
            Some(Arc::new(FakeLock {
                held: lock_held.clone(),
            })),
            Some(Arc::new(FakeInspector {
                bytes: repo_bytes.clone(),
                sealed: 1,
                binding_id,
                device_id: "fs-abc".into(),
            })),
            Some(Arc::new(FakeDatabase)),
            Some(Arc::new(FakeAuthority {
                held: authority_held.clone(),
            })),
            Some(Arc::new(FakeThroughput {
                evidence: evidence(),
            })),
            Some(Arc::new(FakeFacts)),
        )
        .unwrap();
        Harness {
            environment,
            binding_id,
            repo_bytes,
            lock_held,
            authority_held,
        }
    }

    fn planned_operation() -> BackupOperation {
        new_backup_operation(
            Uuid::now_v7(),
            Uuid::now_v7(),
            TargetIdentity {
                system_id: "sys-1".into(),
                database_oid: "16639".into(),
                database: "central".into(),
                config_hash: "cfg".into(),
                epoch: 3,
            },
            time::OffsetDateTime::now_utc(),
        )
        .unwrap()
    }

    fn admitted_from(operation: &BackupOperation) -> BackupOperation {
        operation
            .accept(
                new_backup_accepted_facts(
                    time::OffsetDateTime::now_utc(),
                    TARGET_FP,
                    CONFIG_FP,
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                    PROOF,
                )
                .unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn admission_snapshot_requires_every_capability() {
        assert!(new_backup_environment(None, None, None, None, None, None).is_err());
        assert!(
            new_backup_environment(
                Some(Arc::new(FakeLock {
                    held: Arc::new(AtomicBool::new(true)),
                })),
                None,
                None,
                None,
                None,
                Some(Arc::new(FakeFacts)),
            )
            .is_err()
        );
    }

    #[test]
    fn admission_snapshot_binds_every_capability() {
        let harness = harness();
        let operation = planned_operation();
        let snapshot = harness.environment.admission_snapshot(&operation).unwrap();
        assert!(snapshot.target_lock_held);
        assert!(snapshot.authority_receipt_held);
        assert_eq!(snapshot.capacity.repository_bytes, 4096);
        assert_eq!(snapshot.capacity.sealed_backups, 1);
        assert_eq!(snapshot.capacity.database_bytes, 1 << 20);
        assert_eq!(snapshot.capacity.object_bytes, 1 << 30);
        assert_eq!(snapshot.capacity.record_count, 7);
        assert_eq!(snapshot.capacity.devices.len(), 1);
        assert_eq!(snapshot.capacity.devices[0].device_id, "fs-abc");
        assert_eq!(snapshot.facts.target_lock_proof, PROOF);
        assert_eq!(snapshot.facts.repository_binding_id, harness.binding_id);
        // Admission is single-use: any second call refuses.
        assert!(harness.environment.admission_snapshot(&operation).is_err());
        assert!(
            harness
                .environment
                .admission_snapshot(&planned_operation())
                .is_err()
        );
    }

    #[test]
    fn admission_refuses_nonplanned_operation() {
        let harness = harness();
        let planned = planned_operation();
        let admitted = admitted_from(&planned);
        assert!(harness.environment.admission_snapshot(&admitted).is_err());
        // The lock/authority held flags arrive as booleans, not errors.
        harness.lock_held.store(false, Ordering::SeqCst);
        harness.authority_held.store(false, Ordering::SeqCst);
        let snapshot = harness.environment.admission_snapshot(&planned).unwrap();
        assert!(!snapshot.target_lock_held);
        assert!(!snapshot.authority_receipt_held);
    }

    #[test]
    fn continuation_requires_admitted_operation_and_monotonic_bytes() {
        let harness = harness();
        let planned = planned_operation();
        // Nothing admitted yet → refused.
        assert!(harness.environment.continuation_snapshot(&planned).is_err());
        harness.environment.admission_snapshot(&planned).unwrap();
        // Planned still refuses; the admitted phase of the same
        // operation passes.
        assert!(harness.environment.continuation_snapshot(&planned).is_err());
        let running = admitted_from(&planned);
        let snapshot = harness.environment.continuation_snapshot(&running).unwrap();
        assert_eq!(snapshot.bytes_since_last_guard, 0);
        // Bytes growth is reported; a decrease fails closed.
        harness.repo_bytes.store(8192, Ordering::SeqCst);
        let snapshot = harness.environment.continuation_snapshot(&running).unwrap();
        assert_eq!(snapshot.bytes_since_last_guard, 4096);
        harness.repo_bytes.store(1024, Ordering::SeqCst);
        assert!(harness.environment.continuation_snapshot(&running).is_err());
        // A different operation identity refuses.
        let other = admitted_from(&planned_operation());
        assert!(harness.environment.continuation_snapshot(&other).is_err());
    }
}
