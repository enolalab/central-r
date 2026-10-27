//! `throughput_probe.go` — [`ThroughputProbeRunner`] performs only
//! the unprivileged measured paths. The root helper owns
//! disposable-database load/drop and fixed-object seed/delete; the
//! broker owns attempt acceptance, binding, and cleanup-attested
//! activation. This adapter therefore returns only *pending* raw
//! evidence — `receipt_id`, `probe_completed_at`, `probe_elapsed`,
//! `measured_at`, `expires_at`, `cleanup_state`, and
//! `cleanup_verified_at` are stamped later by the broker boundary,
//! exactly as upstream leaves them zero.

#![forbid(unsafe_code)]

use std::io::Read;
use std::time::Duration;

use central_backup::backup::capacity::{
    MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES, MAXIMUM_THROUGHPUT_PROBE_ELAPSED,
    MINIMUM_DUMP_PROBE_ARCHIVE_BYTES, OBJECT_PROBE_PAYLOAD_BYTES, RecoveryProfile,
};
use central_backup::port::ReadClose;
use central_backup::recovery::profile::{
    BACKUP_THROUGHPUT_RECEIPT_SCHEMA, ThroughputEvidence, ThroughputEvidenceBinding,
};
use central_foundation::failure::Failure;
use uuid::Uuid;

/// `ErrThroughputProbe` — closed, locator-free probe refusal.
fn throughput_probe_unavailable() -> Failure {
    Failure::unavailable("throughput_probe", "recovery throughput probe unavailable")
}

/// `ThroughputProbeRepository` — the bounded measured-write surface
/// the probe runs against.
pub trait ThroughputProbeRepository: Send + Sync {
    /// `MeasureDumpProbe`.
    fn measure_dump_probe(
        &self,
        operation_id: Uuid,
        source: &mut dyn Read,
    ) -> Result<(u64, Duration), Failure>;
    /// `MeasureObjectProbe`.
    fn measure_object_probe(
        &self,
        operation_id: Uuid,
        source: &mut dyn Read,
    ) -> Result<(u64, Duration), Failure>;
}

/// `ThroughputProbeDumpSource` — opens the pinned disposable-database
/// `pg_dump` stream for one probe operation.
pub trait ThroughputProbeDumpSource: Send + Sync {
    /// `OpenThroughputProbeDump`.
    fn open_throughput_probe_dump(&self, operation_id: Uuid)
    -> Result<Box<dyn ReadClose>, Failure>;
}

/// `ThroughputProbeObjectSource` — opens the fixed object fixture
/// payload stream.
pub trait ThroughputProbeObjectSource: Send + Sync {
    /// `OpenBackupThroughputFixture`.
    fn open_backup_throughput_fixture(&self) -> Result<Box<dyn ReadClose>, Failure>;
}

/// `ThroughputProbeRunner` — see the module header.
pub struct ThroughputProbeRunner {
    repository: Box<dyn ThroughputProbeRepository>,
    dump: Box<dyn ThroughputProbeDumpSource>,
    objects: Box<dyn ThroughputProbeObjectSource>,
    profile: RecoveryProfile,
    now: fn() -> time::OffsetDateTime,
}

/// `NewThroughputProbeRunner` — every capability and a valid profile
/// is required.
pub fn new_throughput_probe_runner(
    repository: Option<Box<dyn ThroughputProbeRepository>>,
    dump: Option<Box<dyn ThroughputProbeDumpSource>>,
    objects: Option<Box<dyn ThroughputProbeObjectSource>>,
    profile: RecoveryProfile,
) -> Result<ThroughputProbeRunner, Failure> {
    let (Some(repository), Some(dump), Some(objects)) = (repository, dump, objects) else {
        return Err(throughput_probe_unavailable());
    };
    if profile.validate().is_err() {
        return Err(throughput_probe_unavailable());
    }
    Ok(ThroughputProbeRunner {
        repository,
        dump,
        objects,
        profile,
        now: time::OffsetDateTime::now_utc,
    })
}

impl ThroughputProbeRunner {
    /// `Run` — measures the dump and object paths against the bound
    /// environment and returns the pending receipt; see the module
    /// header for which fields this adapter may legitimately leave
    /// zero.
    pub fn run(
        &self,
        operation_id: Uuid,
        accepted_at: time::OffsetDateTime,
        fixture_load_elapsed: time::Duration,
        binding: ThroughputEvidenceBinding,
    ) -> Result<ThroughputEvidence, Failure> {
        if operation_id.is_nil()
            || operation_id.get_version_num() != 7
            || super::environment::is_zero_time(accepted_at)
            || fixture_load_elapsed <= time::Duration::ZERO
            || binding.validate().is_err()
            || self.profile.validate().is_err()
        {
            return Err(throughput_probe_unavailable());
        }
        let now = (self.now)();
        if now < accepted_at
            || now - accepted_at >= MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || fixture_load_elapsed > now - accepted_at
        {
            return Err(throughput_probe_unavailable());
        }

        let mut dump = self
            .dump
            .open_throughput_probe_dump(operation_id)
            .map_err(|_| throughput_probe_unavailable())?;
        let measure = self
            .repository
            .measure_dump_probe(operation_id, &mut *dump)
            .map_err(|_| throughput_probe_unavailable());
        let close = dump.close();
        let (dump_bytes, dump_elapsed_std) = match (measure, close) {
            (Ok(m), Ok(())) => m,
            _ => return Err(throughput_probe_unavailable()),
        };

        let mut object = self
            .objects
            .open_backup_throughput_fixture()
            .map_err(|_| throughput_probe_unavailable())?;
        let measure = self
            .repository
            .measure_object_probe(operation_id, &mut *object)
            .map_err(|_| throughput_probe_unavailable());
        let close = object.close();
        let (object_bytes, object_elapsed_std) = match (measure, close) {
            (Ok(m), Ok(())) => m,
            _ => return Err(throughput_probe_unavailable()),
        };

        let dump_elapsed =
            time::Duration::try_from(dump_elapsed_std).unwrap_or(time::Duration::MAX);
        let object_elapsed =
            time::Duration::try_from(object_elapsed_std).unwrap_or(time::Duration::MAX);
        let staged_at = (self.now)();
        let probe_elapsed = staged_at - accepted_at;
        let margin = probe_elapsed - fixture_load_elapsed;
        if !(MINIMUM_DUMP_PROBE_ARCHIVE_BYTES..=MAXIMUM_DUMP_PROBE_ARCHIVE_BYTES)
            .contains(&dump_bytes)
            || object_bytes != OBJECT_PROBE_PAYLOAD_BYTES
            || dump_elapsed <= time::Duration::ZERO
            || object_elapsed <= time::Duration::ZERO
            || probe_elapsed <= time::Duration::ZERO
            || probe_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED
            || fixture_load_elapsed > probe_elapsed
            || dump_elapsed > margin
            || object_elapsed > margin - dump_elapsed
        {
            return Err(throughput_probe_unavailable());
        }
        let dump_work = checked_probe_work(dump_bytes, 2)?;
        let object_work = checked_probe_work(object_bytes, 3)?;
        let dump_rate = measured_probe_rate(dump_work, dump_elapsed)?;
        let object_rate = measured_probe_rate(object_work, object_elapsed)?;
        if dump_rate < self.profile.min_throughput_bps
            || object_rate < self.profile.min_throughput_bps
        {
            return Err(throughput_probe_unavailable());
        }
        Ok(ThroughputEvidence {
            schema_version: BACKUP_THROUGHPUT_RECEIPT_SCHEMA.into(),
            receipt_id: Uuid::nil(),
            probe_operation_id: operation_id,
            probe_started_at: accepted_at.to_offset(time::UtcOffset::UTC),
            probe_completed_at: crate::backup::environment::zero_time(),
            probe_elapsed: time::Duration::ZERO,
            measured_at: crate::backup::environment::zero_time(),
            expires_at: crate::backup::environment::zero_time(),
            binding,
            dump_archive_bytes: dump_bytes,
            dump_work_bytes: dump_work,
            dump_elapsed,
            fixture_load_elapsed,
            dump_bytes_per_sec: dump_rate,
            object_payload_bytes: object_bytes,
            object_work_bytes: object_work,
            object_elapsed,
            object_bytes_per_sec: object_rate,
            cleanup_state: String::new(),
            cleanup_verified_at: crate::backup::environment::zero_time(),
        })
    }

    /// Test-only clock injection mirrors upstream's `now` field.
    #[cfg(test)]
    pub(crate) fn set_now(&mut self, now: fn() -> time::OffsetDateTime) {
        self.now = now;
    }
}

/// `checkedProbeWork`.
fn checked_probe_work(bytes: u64, factor: u64) -> Result<u64, Failure> {
    if bytes == 0 || factor == 0 {
        return Err(throughput_probe_unavailable());
    }
    bytes
        .checked_mul(factor)
        .ok_or_else(throughput_probe_unavailable)
}

/// `measuredProbeRate` — bytes/second with the upstream overflow and
/// zero guards.
fn measured_probe_rate(bytes: u64, elapsed: time::Duration) -> Result<u64, Failure> {
    if bytes == 0 || elapsed <= time::Duration::ZERO {
        return Err(throughput_probe_unavailable());
    }
    let nanos =
        u64::try_from(elapsed.whole_nanoseconds()).map_err(|_| throughput_probe_unavailable())?;
    if nanos == 0 {
        return Err(throughput_probe_unavailable());
    }
    bytes
        .checked_mul(1_000_000_000)
        .map(|scaled| scaled / nanos)
        .ok_or_else(throughput_probe_unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_backup::backup::capacity::default_recovery_profile;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

    static TEST_NOW_SECONDS: AtomicI64 = AtomicI64::new(1_800_000_000);
    fn test_now() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(TEST_NOW_SECONDS.load(Ordering::SeqCst)).unwrap()
    }

    struct FakeRead {
        inner: std::io::Cursor<Vec<u8>>,
    }
    impl std::io::Read for FakeRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }
    impl ReadClose for FakeRead {
        fn close(self: Box<Self>) -> Result<(), Failure> {
            Ok(())
        }
    }

    struct FakeRepository {
        dump_bytes: u64,
        dump_millis: u64,
        object_bytes: u64,
        object_millis: u64,
    }
    impl ThroughputProbeRepository for FakeRepository {
        fn measure_dump_probe(
            &self,
            _operation_id: Uuid,
            _source: &mut dyn std::io::Read,
        ) -> Result<(u64, Duration), Failure> {
            Ok((self.dump_bytes, Duration::from_millis(self.dump_millis)))
        }
        fn measure_object_probe(
            &self,
            _operation_id: Uuid,
            _source: &mut dyn std::io::Read,
        ) -> Result<(u64, Duration), Failure> {
            Ok((self.object_bytes, Duration::from_millis(self.object_millis)))
        }
    }

    struct FakeDump;
    impl ThroughputProbeDumpSource for FakeDump {
        fn open_throughput_probe_dump(
            &self,
            _operation_id: Uuid,
        ) -> Result<Box<dyn ReadClose>, Failure> {
            Ok(Box::new(FakeRead {
                inner: std::io::Cursor::new(Vec::new()),
            }))
        }
    }

    struct FakeObjects;
    impl ThroughputProbeObjectSource for FakeObjects {
        fn open_backup_throughput_fixture(&self) -> Result<Box<dyn ReadClose>, Failure> {
            Ok(Box::new(FakeRead {
                inner: std::io::Cursor::new(Vec::new()),
            }))
        }
    }

    fn fp(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    fn binding() -> ThroughputEvidenceBinding {
        ThroughputEvidenceBinding {
            instance_id: Uuid::now_v7(),
            payload_epoch_id: Uuid::now_v7(),
            target_fingerprint: fp(0x11),
            repository_binding_id: Uuid::now_v7(),
            device_mount_set_digest: fp(0x22),
            host_profile_digest: fp(0x23),
            dependency_provisioning_digest: fp(0x24),
            postgres_image_digest: fp(0x25),
            minio_image_digest: fp(0x26),
            pg_dump_tool_digest: fp(0x27),
            pg_dump_tool_version: "16.14".into(),
            config_digest: fp(0x28),
            minio_backup_policy_digest: fp(0x29),
            fixture_digest: fp(0x2a),
            transfer_envelope_version: "central.backup-transfer-envelope/v1".into(),
            transfer_envelope_digest: fp(0x2b),
        }
    }

    fn make_runner(dump_millis: u64, object_millis: u64) -> ThroughputProbeRunner {
        let mut runner = new_throughput_probe_runner(
            Some(Box::new(FakeRepository {
                dump_bytes: MINIMUM_DUMP_PROBE_ARCHIVE_BYTES,
                dump_millis,
                object_bytes: OBJECT_PROBE_PAYLOAD_BYTES,
                object_millis,
            })),
            Some(Box::new(FakeDump)),
            Some(Box::new(FakeObjects)),
            default_recovery_profile(),
        )
        .unwrap();
        runner.set_now(test_now);
        runner
    }

    static PROBE_COUNT: AtomicU64 = AtomicU64::new(0);
    fn operation_id() -> Uuid {
        // Probe IDs must be v7 and distinct; the counter folds in to
        // avoid the rare same-millisecond duplicate.
        let _ = PROBE_COUNT.fetch_add(1, Ordering::SeqCst);
        Uuid::now_v7()
    }

    #[test]
    fn run_returns_pending_evidence_with_measured_rates() {
        let runner = make_runner(2_000, 2_000);
        let accepted_at = test_now() - time::Duration::seconds(60);
        let evidence = runner
            .run(
                operation_id(),
                accepted_at,
                time::Duration::seconds(1),
                binding(),
            )
            .unwrap();
        assert_eq!(evidence.schema_version, BACKUP_THROUGHPUT_RECEIPT_SCHEMA);
        // Pending: the broker stamps receipt/completion/expiry/cleanup.
        assert!(evidence.receipt_id.is_nil());
        assert!(evidence.probe_completed_at.year() == 1);
        assert_eq!(
            evidence.dump_work_bytes,
            2 * MINIMUM_DUMP_PROBE_ARCHIVE_BYTES
        );
        assert_eq!(evidence.object_work_bytes, 3 * OBJECT_PROBE_PAYLOAD_BYTES);
        assert!(evidence.dump_bytes_per_sec >= runner.profile.min_throughput_bps);
        assert!(evidence.object_bytes_per_sec >= runner.profile.min_throughput_bps);
        assert_eq!(evidence.dump_elapsed, time::Duration::seconds(2));
        assert_eq!(evidence.fixture_load_elapsed, time::Duration::seconds(1));
        assert_eq!(evidence.probe_started_at, accepted_at);
    }

    #[test]
    fn run_refuses_invalid_inputs_and_slow_rates() {
        let runner = make_runner(2_000, 2_000);
        let accepted_at = test_now() - time::Duration::seconds(60);
        // Nil / non-v7 operation identities refuse.
        assert!(
            runner
                .run(
                    Uuid::nil(),
                    accepted_at,
                    time::Duration::seconds(1),
                    binding()
                )
                .is_err()
        );
        assert!(
            runner
                .run(
                    Uuid::new_v4(),
                    accepted_at,
                    time::Duration::seconds(1),
                    binding()
                )
                .is_err()
        );
        // Zero accepted time and nonpositive fixture elapsed refuse.
        assert!(
            runner
                .run(
                    operation_id(),
                    crate::backup::environment::zero_time(),
                    time::Duration::seconds(1),
                    binding()
                )
                .is_err()
        );
        assert!(
            runner
                .run(operation_id(), accepted_at, time::Duration::ZERO, binding())
                .is_err()
        );
        // Fixture elapsed may not exceed the probe window.
        assert!(
            runner
                .run(
                    operation_id(),
                    accepted_at,
                    time::Duration::seconds(61),
                    binding()
                )
                .is_err()
        );
        // An invalid binding refuses.
        let mut bad = binding();
        bad.pg_dump_tool_version = "15.0".into();
        assert!(
            runner
                .run(operation_id(), accepted_at, time::Duration::seconds(1), bad)
                .is_err()
        );
        // A measurement slower than the 16 MiB/s admitted floor
        // refuses: 2 × 512 MiB in 65 s ≈ 16.5 MB/s < 16 MiB/s — while
        // still inside the probe window (299 s − 1 s margin).
        let slow = make_runner(65_000, 2_000);
        let wide_accepted = test_now() - time::Duration::seconds(299);
        assert!(
            slow.run(
                operation_id(),
                wide_accepted,
                time::Duration::seconds(1),
                binding()
            )
            .is_err()
        );
    }

    #[test]
    fn run_refuses_out_of_window_and_bounds() {
        let runner = make_runner(2_000, 2_000);
        // Accepted point older than the five-minute window refuses.
        let stale = test_now() - MAXIMUM_THROUGHPUT_PROBE_ELAPSED - time::Duration::seconds(1);
        assert!(
            runner
                .run(operation_id(), stale, time::Duration::seconds(1), binding())
                .is_err()
        );
        // Accepted point in the future refuses.
        let future = test_now() + time::Duration::seconds(1);
        assert!(
            runner
                .run(
                    operation_id(),
                    future,
                    time::Duration::seconds(1),
                    binding()
                )
                .is_err()
        );
    }
}
