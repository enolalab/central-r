//! `pgrestore_linux.go` — the pinned `pg_restore` execution boundary.
//!
//! Destructive database replacement consumes only an already-verified
//! dump bound to the exact protected operation, a separately sealed
//! `central_migration` passfile on fd 3, fixed flags, and a fixed
//! environment. Failures map to the closed [`RestoreRefusalReason`]
//! vocabulary — stderr and target details never escape.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use central_backup::backup::capacity::MAXIMUM_RECOVERY_DEADLINE;
use central_backup::recovery::operation::{RestoreCheckpoint, RestoreOperation, RestorePhase};
use central_backup::recovery::refusal::{RestoreRefusalReason, classify_restore_refusal};
use central_foundation::failure::Failure;
use rustix::process::{Pid, Signal};

use super::pgtool;

/// `pinnedPGRestoreVersion` — same pinned PostgreSQL-tools release as
/// `pg_dump`; any drift refuses.
pub const PINNED_PG_RESTORE_VERSION: &str = "16.14";

/// `pinnedPGRestoreRole` — `central_migration`, the only identity
/// permitted to replace the fixed local database.
const PINNED_RESTORE_ROLE: &str = "central_migration";

fn refusal(reason: RestoreRefusalReason) -> Failure {
    reason.into_failure()
}

/// `RestoreDumpSource` — supplies only the verified immutable dump for
/// the exact protected operation. Deliberately no path argument: a
/// command controller cannot direct `pg_restore` at arbitrary recovery
/// media.
pub trait RestoreDumpSource: Send + Sync {
    /// `OpenVerifiedDump` — the re-verified archive descriptor, bound
    /// to `operation` by the source itself.
    fn open_verified_dump(&self, operation: &RestoreOperation) -> Result<File, Failure>;
}

/// `SealedRestorePassfileProvider` — the broker-delivered
/// `central_migration` credential for one restore invocation. A
/// separate type from the backup provider so a backup credential can
/// never satisfy this boundary by accidental interface reuse.
pub trait SealedRestorePassfileProvider: Send + Sync {
    /// `OpenSealedRestorePassfile`.
    fn open_sealed_restore_passfile(&self, operation: &RestoreOperation) -> Result<File, Failure>;
}

/// `PGRestoreConfig` — only helper-selected installation values; none
/// may be supplied through CLI restore arguments.
pub struct PgRestoreConfig {
    /// Absolute helper-selected binary path.
    pub binary_path: PathBuf,
    /// Exact required version string (`16.14`).
    pub version: String,
    /// Maximum elapsed budget for one restore run.
    pub max_elapsed: Duration,
}

impl PgRestoreConfig {
    fn validate(&self) -> Result<(), Failure> {
        if !self.binary_path.is_absolute()
            || self.version != PINNED_PG_RESTORE_VERSION
            || self.max_elapsed.is_zero()
            || self.max_elapsed > MAXIMUM_RECOVERY_DEADLINE.unsigned_abs()
        {
            return Err(refusal(RestoreRefusalReason::EngineUnavailable));
        }
        Ok(())
    }
}

/// `PGRestore` — the C04 pinned database-replacement adapter. Its
/// caller can choose neither the program, target, dump path,
/// environment, nor credential. The helper/PAM/TTY ceremony and
/// protected-journal transition must happen before this adapter is
/// invoked.
pub struct PgRestore {
    config: PgRestoreConfig,
    dumps: Box<dyn RestoreDumpSource>,
    passfiles: Box<dyn SealedRestorePassfileProvider>,
}

impl PgRestore {
    /// `NewPGRestore` — nil composition is never a working runner.
    pub fn new(
        config: PgRestoreConfig,
        dumps: Box<dyn RestoreDumpSource>,
        passfiles: Box<dyn SealedRestorePassfileProvider>,
    ) -> Result<Self, Failure> {
        config.validate()?;
        Ok(Self {
            config,
            dumps,
            passfiles,
        })
    }

    /// `String` intentionally reports no binary, database, archive, or
    /// credential information — a redacted capability label only.
    pub fn label(&self) -> &'static str {
        if self.config.validate().is_err() {
            "pg_restore_memfd_v1 unavailable"
        } else {
            "pg_restore_memfd_v1"
        }
    }

    /// `Restore` — replaces the fixed local Central database with its
    /// verified custom archive. Process failure, descriptor loss,
    /// source failure, cancellation, or deadline loss return only a
    /// refusal vocabulary entry; the coordinator keeps `applying` so
    /// the same protected operation, not a fresh ticket, is required
    /// to resume.
    pub fn restore_database(&self, operation: &RestoreOperation) -> Result<(), Failure> {
        self.config
            .validate()
            .map_err(|_| refusal(RestoreRefusalReason::EngineUnavailable))?;
        if operation.validate().is_err()
            || operation.phase != RestorePhase::Applying
            || operation.last_checkpoint != RestoreCheckpoint::TicketConsumed
        {
            return Err(refusal(RestoreRefusalReason::StateInvalid));
        }
        let deadline_time = operation
            .started_at
            .checked_add(
                time::Duration::try_from(self.config.max_elapsed).unwrap_or(time::Duration::MAX),
            )
            .ok_or_else(|| refusal(RestoreRefusalReason::CapacityInsufficient))?;
        let now = time::OffsetDateTime::now_utc();
        if now >= deadline_time {
            return Err(refusal(RestoreRefusalReason::CapacityInsufficient));
        }
        let remaining = deadline_time - now;
        let remaining_std = remaining.unsigned_abs();
        // Not enough remaining time budget to safely start the
        // destructive run — a resource-headroom refusal, the same
        // bucket the device-capacity reserve gate reports into.
        if remaining_std < pgtool::MINIMUM_TOOL_BUDGET {
            return Err(refusal(RestoreRefusalReason::CapacityInsufficient));
        }

        let dump = self.dumps.open_verified_dump(operation).map_err(|e| {
            classify_restore_refusal(Some(&e), RestoreRefusalReason::MediaInvalid).into_failure()
        })?;

        let passfile = self
            .passfiles
            .open_sealed_restore_passfile(operation)
            .map_err(|e| {
                classify_restore_refusal(Some(&e), RestoreRefusalReason::EngineUnavailable)
                    .into_failure()
            })?;
        if pgtool::validate_sealed_passfile(&passfile).is_err() {
            drop(passfile);
            return Err(refusal(RestoreRefusalReason::StateInvalid));
        }

        self.run(
            dump,
            passfile,
            &operation.operation_id.to_string(),
            remaining_std,
        )
    }

    /// `run` — one pinned `pg_restore` invocation over the already
    /// verified dump descriptor and an already-validated sealed
    /// passfile. The passfile parent copy is dropped the instant
    /// `spawn` returns; the dump fd is consumed by `Stdio`.
    fn run(
        &self,
        dump: File,
        passfile: File,
        operation_id: &str,
        remaining: Duration,
    ) -> Result<(), Failure> {
        let statement_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        if statement_ms == 0 {
            drop(passfile);
            return Err(refusal(RestoreRefusalReason::CapacityInsufficient));
        }

        let mut command = Command::new(&self.config.binary_path);
        command
            .args([
                "--clean",
                "--if-exists",
                "--exit-on-error",
                "--no-owner",
                "--no-privileges",
                "--no-tablespaces",
                "--no-password",
                "--single-transaction",
            ])
            .arg(format!("--host={}", pgtool::PINNED_PG_HOST))
            .arg(format!("--port={}", pgtool::PINNED_PG_PORT))
            .arg(format!("--username={PINNED_RESTORE_ROLE}"))
            .arg(format!("--dbname={}", pgtool::PINNED_PG_DATABASE))
            .env_clear()
            .envs([
                ("LC_ALL", "C"),
                ("TZ", "UTC"),
                ("PGPASSFILE", "/proc/self/fd/3"),
                ("PGCONNECT_TIMEOUT", "5"),
            ])
            .env("PGAPPNAME", format!("central-restore-{operation_id}"))
            .env("PGOPTIONS", pgtool::pg_options(statement_ms))
            .stdin(Stdio::from(dump))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        crate::sys::audited::pg_tool_command(
            &mut command,
            passfile.as_raw_fd(),
            std::process::id(),
        );

        let child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                drop(passfile);
                return Err(refusal(RestoreRefusalReason::EngineUnavailable));
            }
        };
        // `spawn` has duplicated fd 3; never retain a parent copy while
        // the target database is being replaced.
        drop(passfile);

        let pid = i32::try_from(child.id()).unwrap_or_default();
        let start = pgtool::process_start_time(pid);
        let pidfd = Pid::from_raw(pid).and_then(|p| crate::sys::pidfd::open(p).ok());

        let (tx, rx) = mpsc::channel::<io::Result<ExitStatus>>();
        let mut reaped = child;
        thread::spawn(move || {
            let status = reaped.wait();
            let _ = tx.send(status);
        });

        // Wait bounded by the operation's remaining budget; on expiry
        // run the TERM→KILL settle, then report engine-unavailable.
        // Stderr is discarded by design, so the tool's own reason for a
        // non-zero exit is never available to reclassify — every
        // process-level failure past this point is engine-unavailable.
        let outcome = pgtool::wait_timeout(&rx, remaining);
        let failed = match outcome {
            Some(Ok(status)) => !status.success(),
            Some(Err(_)) => true,
            None => {
                settle_pg_restore(&rx, pid, pidfd.as_ref(), start);
                true
            }
        };
        if failed {
            return Err(refusal(RestoreRefusalReason::EngineUnavailable));
        }
        Ok(())
    }
}

/// `settlePGRestore` — TERM the group, grace, then KILL; reaps through
/// the reaper channel either way so no zombie survives a lost run.
fn settle_pg_restore(
    reaper: &mpsc::Receiver<io::Result<ExitStatus>>,
    pid: i32,
    pidfd: Option<&std::os::fd::OwnedFd>,
    start: u64,
) {
    pgtool::signal_pg_process(pid, pidfd, start, Signal::TERM);
    if pgtool::wait_timeout(reaper, pgtool::CANCEL_GRACE).is_none() {
        pgtool::signal_pg_process(pid, pidfd, start, Signal::KILL);
        let _ = pgtool::wait_timeout(reaper, pgtool::KILL_WAIT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    use central_backup::backup::operation::BACKUP_DATABASE_SCHEMA_VERSION;
    use central_backup::domain::TargetIdentity;

    fn fingerprint() -> String {
        format!("sha256:{}", "ab".repeat(32))
    }

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        }
    }

    fn applying_operation(started_ago: Duration) -> RestoreOperation {
        let now = time::OffsetDateTime::now_utc();
        RestoreOperation {
            operation_id: uuid::Uuid::now_v7(),
            ticket_id: uuid::Uuid::now_v7(),
            backup_id: uuid::Uuid::now_v7(),
            target: target(),
            target_fingerprint: fingerprint(),
            manifest_digest: fingerprint(),
            payload_epoch_id: uuid::Uuid::now_v7(),
            database_schema_version: BACKUP_DATABASE_SCHEMA_VERSION.into(),
            capacity_evidence_digest: fingerprint(),
            security_epoch: 1,
            restore_epoch: 1,
            revision: 1,
            phase: RestorePhase::Applying,
            last_checkpoint: RestoreCheckpoint::TicketConsumed,
            authority_reset_receipt_hash: String::new(),
            started_at: now - time::Duration::try_from(started_ago).unwrap_or(time::Duration::ZERO),
            updated_at: now,
            ready_at: time::OffsetDateTime::UNIX_EPOCH
                .replace_year(1)
                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH),
        }
    }

    struct MemfdPassfile;
    impl SealedRestorePassfileProvider for MemfdPassfile {
        fn open_sealed_restore_passfile(
            &self,
            _operation: &RestoreOperation,
        ) -> Result<File, Failure> {
            crate::sys::memfd::create_sealed(
                "pgpass",
                b"127.0.0.1:55432:central:central_migration:redacted",
            )
            .map(File::from)
        }
    }

    struct StubDump(File);
    impl RestoreDumpSource for StubDump {
        fn open_verified_dump(&self, _operation: &RestoreOperation) -> Result<File, Failure> {
            self.0
                .try_clone()
                .map_err(|_| Failure::internal("backup_pg_tool_unavailable", "dump open failed"))
        }
    }

    struct FailingDump(Failure);
    impl RestoreDumpSource for FailingDump {
        fn open_verified_dump(&self, _operation: &RestoreOperation) -> Result<File, Failure> {
            Err(self.0.clone())
        }
    }

    fn fake_tool(body: &str) -> (std::path::PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("central-pg-tool-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("test dir");
        let path = dir.join("pg_restore");
        let mut f = File::create(&path).expect("script");
        writeln!(f, "#!/bin/sh").expect("script");
        f.write_all(body.as_bytes()).expect("script");
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        (dir, path)
    }

    fn dump_file(dir: &std::path::Path) -> File {
        let path = dir.join("central.dump");
        let mut f = File::create(&path).expect("dump");
        f.write_all(b"PGDMP fake archive").expect("dump");
        f.sync_all().expect("dump");
        File::open(&path).expect("dump")
    }

    fn config(path: PathBuf) -> PgRestoreConfig {
        PgRestoreConfig {
            binary_path: path,
            version: PINNED_PG_RESTORE_VERSION.to_owned(),
            max_elapsed: Duration::from_secs(3600),
        }
    }

    #[test]
    fn config_rejects_caller_shaped_values() {
        let mut c = config(PathBuf::from("/usr/bin/pg_restore"));
        c.binary_path = PathBuf::from("pg_restore");
        assert!(c.validate().is_err());
        c.binary_path = PathBuf::from("/usr/bin/pg_restore");
        c.version = "16.15".into();
        assert!(c.validate().is_err());
        c.version = PINNED_PG_RESTORE_VERSION.into();
        c.max_elapsed = Duration::ZERO;
        assert!(c.validate().is_err());
    }

    #[test]
    fn restore_refuses_wrong_phase_or_checkpoint() {
        let (dir, path) = fake_tool("cat >/dev/null");
        let dump = dump_file(&dir);
        let runner = PgRestore::new(
            config(path),
            Box::new(StubDump(dump)),
            Box::new(MemfdPassfile),
        )
        .expect("runner");
        let mut op = applying_operation(Duration::ZERO);
        op.phase = RestorePhase::Verifying;
        let err = runner.restore_database(&op).expect_err("phase gate");
        assert_eq!(
            RestoreRefusalReason::StateInvalid.as_str(),
            err.code(),
            "wrong phase is state-invalid, never a raw adapter error"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_refuses_exhausted_budget() {
        let (dir, path) = fake_tool("cat >/dev/null");
        let dump = dump_file(&dir);
        let runner = PgRestore::new(
            config(path),
            Box::new(StubDump(dump)),
            Box::new(MemfdPassfile),
        )
        .expect("runner");
        let op = applying_operation(Duration::from_secs(3595));
        let err = runner.restore_database(&op).expect_err("budget gate");
        assert_eq!(
            RestoreRefusalReason::CapacityInsufficient.as_str(),
            err.code()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_maps_source_failure_to_media_invalid() {
        let (dir, path) = fake_tool("cat >/dev/null");
        let runner = PgRestore::new(
            config(path),
            Box::new(FailingDump(Failure::internal("x", "transport failed"))),
            Box::new(MemfdPassfile),
        )
        .expect("runner");
        let op = applying_operation(Duration::ZERO);
        let err = runner.restore_database(&op).expect_err("source failure");
        assert_eq!(RestoreRefusalReason::MediaInvalid.as_str(), err.code());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_runs_pinned_tool_to_completion() {
        let (dir, path) = fake_tool("test -r /proc/self/fd/3 || exit 9\ncat >/dev/null");
        let dump = dump_file(&dir);
        let runner = PgRestore::new(
            config(path),
            Box::new(StubDump(dump)),
            Box::new(MemfdPassfile),
        )
        .expect("runner");
        let op = applying_operation(Duration::ZERO);
        assert!(runner.restore_database(&op).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restore_maps_process_failure_to_engine_unavailable() {
        let (dir, path) = fake_tool("exit 3");
        let dump = dump_file(&dir);
        let runner = PgRestore::new(
            config(path),
            Box::new(StubDump(dump)),
            Box::new(MemfdPassfile),
        )
        .expect("runner");
        let op = applying_operation(Duration::ZERO);
        let err = runner.restore_database(&op).expect_err("nonzero exit");
        assert_eq!(RestoreRefusalReason::EngineUnavailable.as_str(), err.code());
        std::fs::remove_dir_all(&dir).ok();
    }
}
