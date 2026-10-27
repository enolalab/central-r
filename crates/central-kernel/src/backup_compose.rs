//! Production backup-worker compositions — the C01 sealed-backup
//! create worker and the unprivileged half of the C02 throughput
//! probe, ported from upstream `cmd/central-backup/production_linux.go`.
//!
//! Every value the worker touches arrives through an inherited
//! capability or a broker-bound credential — no environment variable,
//! argv field, or path selects a repository, target, role, object
//! bucket, or tool binary. Each composition stage maps to exactly one
//! upstream refusal string; failures are `unavailable` and reveal no
//! locator, credential, or endpoint.

use std::fs::File;
use std::os::fd::BorrowedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use central_adapter_linux::backup::{
    LocalPostgresSocketRetainer, PgDump, PgDumpConfig, PgDumpThroughputProbe, Repository,
    S3BackupObjectSource, SealedPassfileProvider, TargetLockHandoff,
    ThroughputProbePassfileProvider, inspect_repository_descriptor, new_backup_environment,
    new_backup_reader_from_sealed_credential, new_throughput_probe_runner,
    read_sealed_passfile_value,
};
use central_adapter_linux::broker::PRODUCTION_SOCKET_PATH;
use central_adapter_linux::broker::backup_throughput_launch::{
    BACKUP_THROUGHPUT_LAUNCH_ACTIVE, BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED,
    BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED, BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED,
    BackupThroughputTargetLockAttestation, BackupThroughputWorkerContext,
};
use central_adapter_linux::broker::backup_worker_client::{
    BackupThroughputWorkerAuthority, BackupWorkerJournal, BackupWorkerSealer,
};
use central_adapter_linux::broker::backup_worker_credential::{
    BackupThroughputWorkerCredentialClient, BackupWorkerCredentialClient,
};
use central_adapter_postgres::backup::{
    AcceptedFactsReader, CapacityCensusReader, ReadyArtifactObjectReader, ReadyArtifactSource,
    TrustedPayloadEpochSource, backup_target_fingerprint, new_postgres_backup_target_excluder,
    open_runtime_connection, open_throughput_target_connection,
};
use central_adapter_postgres::store_support::BlockingConn;
use central_artifact::port::{ObjectInfo, ObjectRef};
use central_backup::app::BackupCoordinator;
use central_backup::backup::capacity::{DEFAULT_RECOVERY_DEADLINE, default_recovery_profile};
use central_backup::backup::operation::{BackupOperation, BackupPhase, new_backup_operation};
use central_backup::port::{
    BackupAuthorityLease, BackupJournalStore, BackupTargetExcluder, BackupTargetExclusion,
    BackupTargetLockRetainer, BackupThroughputSource, ReadClose,
};
use central_foundation::failure::Failure;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

/// `productionBrokerSocket`.
const PRODUCTION_BROKER_SOCKET: &str = PRODUCTION_SOCKET_PATH;

/// The pinned `pg_dump` binary path upstream bakes into
/// `PGDumpConfig{BinaryPath: "/usr/lib/postgresql/16/bin/pg_dump"}`.
const PINNED_PG_DUMP_BINARY: &str = "/usr/lib/postgresql/16/bin/pg_dump";

/// `PINNED_PG_DUMP_VERSION` re-exported for the composition literal.
const PINNED_PG_DUMP_VERSION_STRING: &str = "16.14";

fn unavailable(message: &'static str) -> Failure {
    Failure::unavailable("backup_worker_composition", message)
}

/// `fixedPayloadEpochSource` — the probe composition's pinned epoch:
/// it must never consult protected paths or restore history, exactly
/// like upstream.
struct FixedPayloadEpochSource {
    payload_epoch_id: Uuid,
}

impl TrustedPayloadEpochSource for FixedPayloadEpochSource {
    fn active_payload_epoch_id(&self) -> Result<Uuid, Failure> {
        if self.payload_epoch_id.is_nil() || self.payload_epoch_id.get_version_num() != 7 {
            return Err(Failure::unavailable(
                "backup_worker_composition",
                "backup throughput payload epoch unavailable",
            ));
        }
        Ok(self.payload_epoch_id)
    }
}

/// The create worker's epoch source: the broker journal is the only
/// trusted view of the active payload generation.
struct WorkerEpochSource {
    journal: Arc<BackupWorkerJournal>,
}

impl TrustedPayloadEpochSource for WorkerEpochSource {
    fn active_payload_epoch_id(&self) -> Result<Uuid, Failure> {
        self.journal.active_payload_epoch_id()
    }
}

/// `SealedPassfileProvider` over the operation-bound worker credential
/// client — the provider decides which credential draw the operation
/// may make, exactly like upstream passing `credentials` into
/// `NewPGDump`.
struct WorkerPassfileProvider {
    credentials: Arc<BackupWorkerCredentialClient>,
}

impl SealedPassfileProvider for WorkerPassfileProvider {
    fn open_sealed_passfile(&self, operation: &BackupOperation) -> Result<File, Failure> {
        self.credentials
            .open_sealed_passfile(operation)
            .map(File::from)
    }
}

/// `throughputProbePassfileProvider` — narrows the throughput
/// credential client to the probe passfile draw.
struct ProbePassfileProvider {
    credentials: Arc<BackupThroughputWorkerCredentialClient>,
}

impl ThroughputProbePassfileProvider for ProbePassfileProvider {
    fn open_throughput_probe_passfile(&self, operation_id: Uuid) -> Result<File, Failure> {
        self.credentials
            .open_postgres_probe_passfile(operation_id)
            .map(File::from)
    }
}

/// `ReadyArtifactObjectReader` over the sync S3 backup-object source —
/// the kernel's one-line bridge upstream leaves to the composition
/// root (`postgres.NewReadyArtifactSource(connection, objects)`).
struct WorkerObjectReader {
    objects: Arc<S3BackupObjectSource>,
}

impl ReadyArtifactObjectReader for WorkerObjectReader {
    fn read(&self, reference: &ObjectRef) -> Result<(Box<dyn ReadClose>, ObjectInfo), Failure> {
        self.objects.read_ready_object(reference)
    }
}

/// `decodeTargetLockProof` — `sha256:` + 64 lowercase hex into the
/// raw proof digest; a zero digest refuses.
fn decode_target_lock_proof(value: &str) -> Result<[u8; 32], Failure> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(unavailable("backup throughput target proof unavailable"));
    };
    if hex.len() != 64 {
        return Err(unavailable("backup throughput target proof unavailable"));
    }
    let mut proof = [0u8; 32];
    for (i, byte) in proof.iter_mut().enumerate() {
        let hi = hex.as_bytes()[i * 2];
        let lo = hex.as_bytes()[i * 2 + 1];
        let (Some(h), Some(l)) = (hex_digit(hi), hex_digit(lo)) else {
            return Err(unavailable("backup throughput target proof unavailable"));
        };
        *byte = (h << 4) | l;
    }
    if proof == [0u8; 32] {
        return Err(unavailable("backup throughput target proof unavailable"));
    }
    Ok(proof)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// `retainTargetLockDescriptor` — upstream converts the borrowed
/// socket into a short-lived duplicate whose close after the
/// SCM_RIGHTS ack does not touch the lease's original. The retainer
/// already hands this callback a fresh `F_DUPFD_CLOEXEC` borrow, so
/// the Rust half is the handoff call itself.
fn retain_target_lock_descriptor(
    handoff: &mut TargetLockHandoff,
    socket: BorrowedFd<'_>,
    proof: [u8; 32],
    deadline: Option<OffsetDateTime>,
) -> Result<(), Failure> {
    if proof == [0u8; 32] {
        return Err(unavailable("backup worker target retention is unavailable"));
    }
    // `conn.SetDeadline(ctx.Deadline())` — the probe's deadline-bound
    // exchange; the create worker runs deadline-free like upstream's
    // background context.
    let timeout = deadline.map(|d| {
        let remaining = d - OffsetDateTime::now_utc();
        if remaining.is_positive() {
            Duration::from_nanos(remaining.whole_nanoseconds() as u64)
        } else {
            Duration::from_nanos(0)
        }
    });
    handoff
        .retain_target_lock(socket, proof, timeout)
        .map_err(|_| unavailable("backup worker target retention is unavailable"))
}

/// `(productionBackupWorker).Run` — composes the fixed C01 worker
/// entirely from inherited capabilities and broker-bound credentials.
///
/// The `repository_fd` must be the supervisor's inherited FD 4, already
/// made `FD_CLOEXEC` by the launcher grammar; FD 5 (the CBW1 monitor
/// channel) is adopted and sealed before any network connection or
/// subprocess exists.
///
/// # Errors
/// Exactly the upstream refusal strings — no stage leaks a locator.
pub fn run_backup_worker(
    launch_evidence_id: Uuid,
    operation_id: Uuid,
    repository_fd: BorrowedFd<'_>,
) -> Result<(), Failure> {
    if launch_evidence_id.is_nil() || operation_id.is_nil() {
        return Err(unavailable(
            "backup worker production composition is unavailable",
        ));
    }
    // Adopt and CLOEXEC FD 5 before opening a network connection or
    // spawning a child — the monitor channel can therefore never leak
    // into pg_dump.
    let mut handoff = TargetLockHandoff::prepare()
        .map_err(|_| unavailable("backup worker production composition is unavailable"))?;

    let journal = Arc::new(BackupWorkerJournal::new(
        PathBuf::from(PRODUCTION_BROKER_SOCKET),
        launch_evidence_id,
        operation_id,
    ));
    let authority = journal
        .authority()
        .map_err(|_| unavailable("backup worker authority is unavailable"))?;
    if authority.operation_id != operation_id || authority.backup_id.is_nil() {
        return Err(unavailable("backup worker authority is unavailable"));
    }
    let binding = inspect_repository_descriptor(repository_fd)
        .map_err(|_| unavailable("backup worker repository is unavailable"))?;
    let repository = Arc::new(
        Repository::from_descriptor(repository_fd, &binding)
            .map_err(|_| unavailable("backup worker repository is unavailable"))?,
    );
    // Upstream `defer repository.Close()` — the owned descriptors and
    // the flock release on drop.

    let credentials = Arc::new(BackupWorkerCredentialClient::new(
        PRODUCTION_BROKER_SOCKET.to_owned(),
        launch_evidence_id,
        operation_id,
    ));
    let passfile = credentials
        .open_postgres_runtime_credential()
        .map_err(|_| unavailable("backup worker database authority is unavailable"))?;
    let value = Zeroizing::new(
        read_sealed_passfile_value(&passfile)
            .map_err(|_| unavailable("backup worker database is unavailable"))?,
    );
    drop(passfile);
    // `new_connecting` binds the session socket to the bridge's own
    // runtime — the connection the retainer later locates is exactly
    // this process socket.
    let conn = Arc::new(
        BlockingConn::new_connecting(|| open_runtime_connection(&value))
            .map_err(|_| unavailable("backup worker database is unavailable"))?,
    );
    drop(value);

    let facts = Arc::new(
        AcceptedFactsReader::new(
            conn.clone(),
            Arc::new(WorkerEpochSource {
                journal: journal.clone(),
            }),
        )
        .map_err(|_| unavailable("backup worker accepted facts are unavailable"))?,
    );
    let target = facts
        .read_backup_target()
        .map_err(|_| unavailable("backup worker target is unavailable"))?;
    let operation = new_backup_operation(
        operation_id,
        authority.backup_id,
        target.clone(),
        OffsetDateTime::now_utc(),
    )
    .map_err(|_| unavailable("backup worker operation is unavailable"))?;
    let excluder = new_postgres_backup_target_excluder(conn.clone())
        .map_err(|_| unavailable("backup worker target exclusion is unavailable"))?;
    let lease = excluder
        .acquire_backup_target_exclusion(&target)
        .map_err(|_| unavailable("backup worker target exclusion is unavailable"))?;

    let census = Arc::new(
        CapacityCensusReader::new(conn.clone())
            .map_err(|_| unavailable("backup worker capacity source is unavailable"))?,
    );
    let environment = new_backup_environment(
        Some(lease.clone()),
        Some(repository.clone()),
        Some(census),
        Some(journal.clone() as Arc<dyn BackupAuthorityLease>),
        Some(journal.clone() as Arc<dyn BackupThroughputSource>),
        Some(facts),
    )
    .map_err(|_| {
        let _ = lease.release();
        unavailable("backup worker environment is unavailable")
    })?;
    let minio_credential = credentials
        .open_minio_backup_credential()
        .map_err(|_| unavailable("backup worker object authority is unavailable"))?;
    let store = new_backup_reader_from_sealed_credential(File::from(minio_credential))
        .map_err(|_| unavailable("backup worker object source is unavailable"))?;
    let object_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("central-backup-objects")
        .build()
        .map_err(|_| unavailable("backup worker object source is unavailable"))?;
    let objects = Arc::new(
        S3BackupObjectSource::new(Arc::new(store), object_runtime.handle().clone())
            .map_err(|_| unavailable("backup worker object source is unavailable"))?,
    );
    let artifacts = ReadyArtifactSource::new(
        conn.clone(),
        Arc::new(WorkerObjectReader {
            objects: objects.clone(),
        }),
    )
    .map_err(|_| unavailable("backup worker artifact source is unavailable"))?;
    let dumper = PgDump::new(
        PgDumpConfig {
            binary_path: PathBuf::from(PINNED_PG_DUMP_BINARY),
            version: PINNED_PG_DUMP_VERSION_STRING.to_owned(),
            max_elapsed: DEFAULT_RECOVERY_DEADLINE.unsigned_abs(),
        },
        Box::new(WorkerPassfileProvider {
            credentials: credentials.clone(),
        }),
    )
    .map_err(|_| unavailable("backup worker dump tool is unavailable"))?;
    let sealer =
        BackupWorkerSealer::new(PathBuf::from(PRODUCTION_BROKER_SOCKET), launch_evidence_id);
    let coordinator = BackupCoordinator::new(
        &*journal as &dyn BackupJournalStore,
        &environment,
        &*repository,
        &artifacts,
        &dumper,
        &sealer,
        default_recovery_profile(),
    );
    let result = coordinator.run(operation).map_err(|_| {
        let _ = lease.release();
        unavailable("backup worker publication failed")
    })?;
    let (Some(manifest), Some(publication)) = (&result.manifest, &result.publication) else {
        let _ = lease.release();
        return Err(unavailable("backup worker publication failed"));
    };
    if result.operation.phase != BackupPhase::Sealing
        || publication.validate().is_err()
        || publication.operation_id != manifest.operation_id
        || publication.backup_id != manifest.backup_id
        || publication.repository_binding_id != manifest.repository_binding_id
        || publication.root_manifest_digest != manifest.digest
    {
        let _ = lease.release();
        return Err(unavailable("backup worker publication failed"));
    }
    let retainer = LocalPostgresSocketRetainer::new(lease.clone());
    let mut cb = |socket: BorrowedFd<'_>, proof: [u8; 32]| {
        retain_target_lock_descriptor(&mut handoff, socket, proof, None)
    };
    retainer.retain_for_post_reap(&mut cb).map_err(|_| {
        let _ = lease.release();
        unavailable("backup worker target retention failed")
    })?;
    // `retained = true` — the monitor owns the session continuation;
    // no release, no close of the lease's session here.
    drop(object_runtime);
    Ok(())
}

/// `throughputWorkerContextSource` — the narrow poll seam upstream
/// carves out of the authority so the wait loop stays testable.
trait WorkerContextSource {
    fn worker_context(&self) -> Result<BackupThroughputWorkerContext, Failure>;
}

impl WorkerContextSource for BackupThroughputWorkerAuthority {
    fn worker_context(&self) -> Result<BackupThroughputWorkerContext, Failure> {
        Self::worker_context(self)
    }
}

/// `waitForThroughputFixture` — polls the broker worker context until
/// the privileged fixture half reports `fixture_loaded`, refusing on
/// any phase or binding deviation. `deadline` is the launch's
/// authoritative bound (upstream's `probeCtx`).
fn wait_for_throughput_fixture(
    authority: &dyn WorkerContextSource,
    launch_evidence_id: Uuid,
    operation_id: Uuid,
    target_fingerprint: &str,
    deadline: OffsetDateTime,
) -> Result<BackupThroughputWorkerContext, Failure> {
    if launch_evidence_id.is_nil() || operation_id.is_nil() || target_fingerprint.is_empty() {
        return Err(unavailable("backup throughput fixture unavailable"));
    }
    loop {
        let current = authority
            .worker_context()
            .map_err(|_| unavailable("backup throughput fixture unavailable"))?;
        if current.launch_evidence_id != launch_evidence_id
            || current.operation_id != operation_id
            || current.target_fingerprint != target_fingerprint
        {
            return Err(unavailable("backup throughput fixture unavailable"));
        }
        match current.phase.as_str() {
            BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED => {
                if current.fixture_load_elapsed <= time::Duration::ZERO
                    || current.provision_receipt_binding.is_empty()
                {
                    return Err(unavailable("backup throughput fixture unavailable"));
                }
                return Ok(current);
            }
            BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED => {}
            BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED => {
                return Err(unavailable("backup throughput fixture unavailable"));
            }
            _ => return Err(unavailable("backup throughput fixture unavailable")),
        }
        if OffsetDateTime::now_utc() >= deadline {
            return Err(unavailable("backup throughput fixture unavailable"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `(productionThroughputProbeWorker).RunThroughputProbe` — the
/// unprivileged half of C02. The root helper creates/loads and later
/// drops the disposable database and owns the fixed MinIO fixture
/// lifecycle; this worker keeps the exact target exclusion for the
/// whole measurement, stages pending evidence, then transfers the
/// lock socket to the per-launch native monitor for post-reap cleanup
/// attestation.
///
/// # Errors
/// Exactly the upstream refusal strings.
pub fn run_throughput_probe_worker(
    launch_evidence_id: Uuid,
    operation_id: Uuid,
    repository_fd: BorrowedFd<'_>,
) -> Result<(), Failure> {
    if launch_evidence_id.is_nil() || operation_id.is_nil() || operation_id.get_version_num() != 7 {
        return Err(unavailable(
            "backup throughput probe production composition is unavailable",
        ));
    }
    let mut handoff = TargetLockHandoff::prepare()
        .map_err(|_| unavailable("backup throughput probe target retention is unavailable"))?;

    let authority = BackupThroughputWorkerAuthority::new(
        PathBuf::from(PRODUCTION_BROKER_SOCKET),
        launch_evidence_id,
        operation_id,
    );
    let worker_context = authority
        .worker_context()
        .map_err(|_| unavailable("backup throughput probe authority is unavailable"))?;
    if worker_context.phase != BACKUP_THROUGHPUT_LAUNCH_ACTIVE
        || worker_context.launch_evidence_id != launch_evidence_id
        || worker_context.operation_id != operation_id
        || worker_context.static_binding.validate().is_err()
        || worker_context.static_binding.repository_binding_id.is_nil()
        || OffsetDateTime::now_utc() >= worker_context.deadline
    {
        return Err(unavailable(
            "backup throughput probe authority is unavailable",
        ));
    }
    let deadline = worker_context.deadline;

    let binding = inspect_repository_descriptor(repository_fd)
        .map_err(|_| unavailable("backup throughput probe repository is unavailable"))?;
    if binding.binding_id != worker_context.static_binding.repository_binding_id {
        return Err(unavailable(
            "backup throughput probe repository is unavailable",
        ));
    }
    // The probe shares the repository with no second consumer — the
    // runner owns it directly (upstream's single `repository` value).
    let repository = Repository::from_descriptor(repository_fd, &binding)
        .map_err(|_| unavailable("backup throughput probe repository is unavailable"))?;

    let credentials = Arc::new(BackupThroughputWorkerCredentialClient::new(
        PRODUCTION_BROKER_SOCKET.to_owned(),
        launch_evidence_id,
        operation_id,
    ));
    let target_passfile = credentials
        .open_postgres_target_passfile(operation_id)
        .map_err(|_| unavailable("backup throughput probe target authority is unavailable"))?;
    let value = Zeroizing::new(
        read_sealed_passfile_value(&target_passfile)
            .map_err(|_| unavailable("backup throughput probe target is unavailable"))?,
    );
    drop(target_passfile);
    let conn = Arc::new(
        BlockingConn::new_connecting(|| open_throughput_target_connection(&value, operation_id))
            .map_err(|_| unavailable("backup throughput probe target is unavailable"))?,
    );
    drop(value);
    let facts = AcceptedFactsReader::new(
        conn.clone(),
        Arc::new(FixedPayloadEpochSource {
            payload_epoch_id: worker_context.static_binding.payload_epoch_id,
        }),
    )
    .map_err(|_| unavailable("backup throughput probe target facts are unavailable"))?;
    let target = facts
        .read_backup_target()
        .map_err(|_| unavailable("backup throughput probe target facts are unavailable"))?;
    let target_fingerprint =
        backup_target_fingerprint(&target, worker_context.static_binding.payload_epoch_id)
            .map_err(|_| unavailable("backup throughput probe target facts are unavailable"))?;
    let excluder = new_postgres_backup_target_excluder(conn.clone())
        .map_err(|_| unavailable("backup throughput probe target exclusion is unavailable"))?;
    let lease = excluder
        .acquire_backup_target_exclusion(&target)
        .map_err(|_| unavailable("backup throughput probe target exclusion is unavailable"))?;
    let target_lock_proof = decode_target_lock_proof(&lease.proof()).map_err(|_| {
        let _ = lease.release();
        unavailable("backup throughput probe target evidence is unavailable")
    })?;
    authority
        .mark_target_locked(&BackupThroughputTargetLockAttestation {
            target_fingerprint: target_fingerprint.clone(),
            target_lock_proof_sha256: target_lock_proof,
            locked_at: OffsetDateTime::now_utc(),
        })
        .map_err(|_| {
            let _ = lease.release();
            unavailable("backup throughput probe target evidence is unavailable")
        })?;

    let loaded_context = wait_for_throughput_fixture(
        &authority,
        launch_evidence_id,
        operation_id,
        &target_fingerprint,
        deadline,
    )
    .map_err(|_| {
        let _ = lease.release();
        unavailable("backup throughput probe fixture is unavailable")
    })?;
    let full_binding = loaded_context
        .static_binding
        .with_target_fingerprint(&target_fingerprint)
        .map_err(|_| {
            let _ = lease.release();
            unavailable("backup throughput probe binding is unavailable")
        })?;
    let remaining = loaded_context.deadline - OffsetDateTime::now_utc();
    if !remaining.is_positive() {
        let _ = lease.release();
        return Err(unavailable("backup throughput probe dump is unavailable"));
    }
    let dump = PgDumpThroughputProbe::new(
        PgDumpConfig {
            binary_path: PathBuf::from(PINNED_PG_DUMP_BINARY),
            version: PINNED_PG_DUMP_VERSION_STRING.to_owned(),
            max_elapsed: remaining.unsigned_abs(),
        },
        Box::new(ProbePassfileProvider {
            credentials: credentials.clone(),
        }),
    )
    .map_err(|_| {
        let _ = lease.release();
        unavailable("backup throughput probe dump is unavailable")
    })?;
    let minio_credential = credentials
        .open_minio_probe_credential()
        .map_err(|_| unavailable("backup throughput probe object authority is unavailable"))?;
    let store = new_backup_reader_from_sealed_credential(File::from(minio_credential))
        .map_err(|_| unavailable("backup throughput probe object source is unavailable"))?;
    let object_runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("central-backup-probe-objects")
        .build()
        .map_err(|_| unavailable("backup throughput probe object source is unavailable"))?;
    let objects = S3BackupObjectSource::new(Arc::new(store), object_runtime.handle().clone())
        .map_err(|_| unavailable("backup throughput probe object source is unavailable"))?;
    let runner = new_throughput_probe_runner(
        Some(Box::new(repository)),
        Some(Box::new(dump)),
        Some(Box::new(objects)),
        default_recovery_profile(),
    )
    .map_err(|_| {
        let _ = lease.release();
        unavailable("backup throughput probe runner is unavailable")
    })?;
    let evidence = runner
        .run(
            operation_id,
            loaded_context.accepted_at,
            loaded_context.fixture_load_elapsed,
            full_binding,
        )
        .map_err(|_| {
            let _ = lease.release();
            unavailable("backup throughput probe measurement failed")
        })?;
    authority
        .stage(&evidence, OffsetDateTime::now_utc())
        .map_err(|_| {
            let _ = lease.release();
            unavailable("backup throughput probe measurement failed")
        })?;
    lease.assert_held().map_err(|_| {
        let _ = lease.release();
        unavailable("backup throughput probe measurement failed")
    })?;
    let retainer = LocalPostgresSocketRetainer::new(lease.clone());
    let mut cb = |socket: BorrowedFd<'_>, proof: [u8; 32]| {
        if proof != target_lock_proof {
            return Err(unavailable("backup throughput probe target proof changed"));
        }
        retain_target_lock_descriptor(&mut handoff, socket, proof, Some(deadline))
    };
    retainer.retain_for_post_reap(&mut cb).map_err(|_| {
        let _ = lease.release();
        unavailable("backup throughput probe target retention failed")
    })?;
    drop(object_runtime);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use central_adapter_linux::broker::backup_throughput_launch::static_backup_throughput_binding;
    use central_backup::recovery::profile::ThroughputEvidenceBinding;
    use std::sync::Mutex;

    fn fp(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    /// `decodeTargetLockProof` — the exact shape gate.
    #[test]
    fn target_lock_proof_decode_is_exact() {
        let valid = fp(0x44);
        let proof = decode_target_lock_proof(&valid).unwrap();
        assert_eq!(proof, [0x44; 32]);

        assert!(decode_target_lock_proof(&proof[0..0].escape_ascii().to_string()).is_err());
        assert!(decode_target_lock_proof("sha256:zz").is_err());
        assert!(decode_target_lock_proof(&valid[..valid.len() - 2]).is_err());
        // No prefix / wrong length / non-hex / all-zero refuse.
        assert!(decode_target_lock_proof(&"44".repeat(32)).is_err());
        assert!(decode_target_lock_proof(&format!("sha256:{}", "gg".repeat(32))).is_err());
        assert!(decode_target_lock_proof(&fp(0x00)).is_err());
    }

    /// `fixedPayloadEpochSource` — v7-bound, refuses nil and foreign
    /// versions without consulting anything else.
    #[test]
    fn fixed_epoch_source_is_v7_bound() {
        let id = Uuid::now_v7();
        let source = FixedPayloadEpochSource {
            payload_epoch_id: id,
        };
        assert_eq!(source.active_payload_epoch_id().unwrap(), id);
        let nil = FixedPayloadEpochSource {
            payload_epoch_id: Uuid::nil(),
        };
        assert!(nil.active_payload_epoch_id().is_err());
        let v4 = FixedPayloadEpochSource {
            payload_epoch_id: Uuid::new_v4(),
        };
        assert!(v4.active_payload_epoch_id().is_err());
    }

    struct FakeContexts {
        contexts: Mutex<std::collections::VecDeque<BackupThroughputWorkerContext>>,
    }

    impl WorkerContextSource for FakeContexts {
        fn worker_context(&self) -> Result<BackupThroughputWorkerContext, Failure> {
            self.contexts
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| Failure::unavailable("test", "no context"))
        }
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

    fn context(
        phase: &str,
        evidence_id: Uuid,
        operation_id: Uuid,
        target_fingerprint: &str,
    ) -> BackupThroughputWorkerContext {
        let now = OffsetDateTime::now_utc();
        BackupThroughputWorkerContext {
            launch_evidence_id: evidence_id,
            operation_id,
            phase: phase.into(),
            accepted_at: now,
            deadline: now + time::Duration::minutes(5),
            static_binding: static_backup_throughput_binding(&binding()),
            target_fingerprint: target_fingerprint.into(),
            fixture_load_elapsed: time::Duration::ZERO,
            provision_receipt_binding: String::new(),
        }
    }

    /// `waitForThroughputFixture` — the exact upstream phase ladder:
    /// target_locked polls until fixture_loaded; staged/unknown/misbound
    /// phases and zero elapsed refuse.
    #[test]
    fn fixture_wait_follows_the_phase_ladder() {
        let evidence_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let fingerprint = fp(0x11);
        let deadline = OffsetDateTime::now_utc() + time::Duration::seconds(30);

        // target_locked → fixture_loaded returns the loaded context.
        let mut loaded = context(
            BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED,
            evidence_id,
            operation_id,
            &fingerprint,
        );
        loaded.fixture_load_elapsed = time::Duration::seconds(7);
        loaded.provision_receipt_binding = fp(0x50);
        let source = FakeContexts {
            contexts: Mutex::new(
                [
                    context(
                        BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED,
                        evidence_id,
                        operation_id,
                        &fingerprint,
                    ),
                    loaded.clone(),
                ]
                .into(),
            ),
        };
        let got =
            wait_for_throughput_fixture(&source, evidence_id, operation_id, &fingerprint, deadline)
                .unwrap();
        assert_eq!(got.phase, BACKUP_THROUGHPUT_LAUNCH_FIXTURE_LOADED);
        assert_eq!(got.fixture_load_elapsed, time::Duration::seconds(7));

        // measurement_staged refuses outright.
        let source = FakeContexts {
            contexts: Mutex::new(
                [context(
                    BACKUP_THROUGHPUT_LAUNCH_MEASUREMENT_STAGED,
                    evidence_id,
                    operation_id,
                    &fingerprint,
                )]
                .into(),
            ),
        };
        assert!(
            wait_for_throughput_fixture(&source, evidence_id, operation_id, &fingerprint, deadline)
                .is_err()
        );

        // fixture_loaded with zero elapsed refuses.
        let mut zero = loaded.clone();
        zero.fixture_load_elapsed = time::Duration::ZERO;
        let source = FakeContexts {
            contexts: Mutex::new([zero].into()),
        };
        assert!(
            wait_for_throughput_fixture(&source, evidence_id, operation_id, &fingerprint, deadline)
                .is_err()
        );

        // A foreign fingerprint refuses.
        let mut foreign = loaded.clone();
        foreign.target_fingerprint = fp(0x99);
        let source = FakeContexts {
            contexts: Mutex::new([foreign].into()),
        };
        assert!(
            wait_for_throughput_fixture(&source, evidence_id, operation_id, &fingerprint, deadline)
                .is_err()
        );

        // An exhausted deadline on a still-locked context refuses.
        let source = FakeContexts {
            contexts: Mutex::new(
                std::iter::repeat_with(|| {
                    context(
                        BACKUP_THROUGHPUT_LAUNCH_TARGET_LOCKED,
                        evidence_id,
                        operation_id,
                        &fingerprint,
                    )
                })
                .take(64)
                .collect(),
            ),
        };
        let past = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        assert!(
            wait_for_throughput_fixture(&source, evidence_id, operation_id, &fingerprint, past)
                .is_err()
        );
    }
}
