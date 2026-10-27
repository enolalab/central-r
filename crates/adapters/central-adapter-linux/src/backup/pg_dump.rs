//! `pgdump_linux.go` — the pinned `pg_dump` execution boundary.
//!
//! One custom-format `pg_dump` per call, fixed flags, fixed target,
//! fixed environment, broker-supplied sealed passfile on child fd 3.
//! Callers receive stdout only; `close` reaps the child and reports a
//! single redacted process failure — never stderr, paths, commands,
//! target details, or credential material.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use central_backup::backup::capacity::MAXIMUM_RECOVERY_DEADLINE;
use central_backup::backup::operation::{BackupOperation, BackupPhase};
use central_backup::port::{BackupDumper, ReadClose};
use central_foundation::failure::Failure;
use rustix::process::{Pid, Signal};

use super::pgtool;

/// `pinnedPGDumpVersion` — the exact PostgreSQL-tools release the
/// trusted helper installs; any drift refuses.
pub const PINNED_PG_DUMP_VERSION: &str = "16.14";

/// `pinnedPGRole` — `central_runtime`, never `central_migration`.
pub(super) const PINNED_BACKUP_ROLE: &str = "central_runtime";

/// The one redacted process-boundary failure (upstream
/// `errDumpProcessUnavailable`). Stable code only.
fn dump_unavailable() -> Failure {
    Failure::unavailable(
        "backup_pg_dump_unavailable",
        "pg dump process boundary unavailable",
    )
}

/// `SealedPassfileProvider` — supplies one broker-delivered, sealed
/// passfile descriptor for a single `pg_dump` invocation. The
/// credential never becomes a string in this adapter; the parent
/// closes its descriptor immediately after spawn and only fd 3
/// remains open in the child.
pub trait SealedPassfileProvider: Send + Sync {
    /// `OpenSealedPassfile` — the caller hands the operation; the
    /// provider decides which credential draw is authorized.
    fn open_sealed_passfile(&self, operation: &BackupOperation) -> Result<File, Failure>;
}

/// `PGDumpConfig` — only fixed, non-secret installation values.
/// Command input cannot select a binary, host, role, database, or
/// connection target.
pub struct PgDumpConfig {
    /// Absolute helper-selected binary path.
    pub binary_path: PathBuf,
    /// Exact required version string (`16.14`).
    pub version: String,
    /// Maximum elapsed budget for one dump (bounded by
    /// `MAXIMUM_RECOVERY_DEADLINE`).
    pub max_elapsed: Duration,
}

impl PgDumpConfig {
    pub(super) fn validate(&self) -> Result<(), Failure> {
        if !self.binary_path.is_absolute()
            || self.version != PINNED_PG_DUMP_VERSION
            || self.max_elapsed.is_zero()
            || self.max_elapsed > MAXIMUM_RECOVERY_DEADLINE.unsigned_abs()
        {
            return Err(dump_unavailable());
        }
        Ok(())
    }
}

/// `PGDump` — the C01 host-tool adapter. Implements
/// [`BackupDumper`] without permitting a caller-selected program,
/// argument, environment, or credential file path.
pub struct PgDump {
    config: PgDumpConfig,
    passfiles: Box<dyn SealedPassfileProvider>,
}

impl PgDump {
    /// `NewPGDump` — both halves are required; a nil composition is
    /// never a working dumper.
    pub fn new(
        config: PgDumpConfig,
        passfiles: Box<dyn SealedPassfileProvider>,
    ) -> Result<Self, Failure> {
        config.validate()?;
        Ok(Self { config, passfiles })
    }

    /// `String` deliberately reports no command, environment, target
    /// or credential details — a redacted capability label only.
    pub fn label(&self) -> &'static str {
        if self.config.validate().is_err() {
            "pg_tool_memfd_v1 unavailable"
        } else {
            "pg_tool_memfd_v1"
        }
    }
}

impl BackupDumper for PgDump {
    /// `StartDump` — starts exactly one pinned custom-format `pg_dump`.
    /// The returned stream is stdout only; `close` reaps the child and
    /// returns a redacted process failure when the tool did not
    /// complete successfully.
    fn start_dump(&self, operation: &BackupOperation) -> Result<Box<dyn ReadClose>, Failure> {
        self.config.validate()?;
        // The operation must already sit at `dumping` with a valid
        // accepted point — the adapter never derives them. The
        // year-1 timestamp is the domain's Go zero `time.Time`
        // equivalent (`wire::zero_time`).
        if operation.phase != BackupPhase::Dumping || operation.accepted_at.year() == 1 {
            return Err(dump_unavailable());
        }
        let deadline_time = operation
            .accepted_at
            .checked_add(
                time::Duration::try_from(self.config.max_elapsed).unwrap_or(time::Duration::MAX),
            )
            .ok_or_else(dump_unavailable)?;
        let now = time::OffsetDateTime::now_utc();
        if now >= deadline_time {
            return Err(dump_unavailable());
        }
        let remaining = deadline_time - now;
        let remaining_std = remaining.unsigned_abs();
        if remaining_std < pgtool::MINIMUM_TOOL_BUDGET {
            return Err(dump_unavailable());
        }

        let passfile = self
            .passfiles
            .open_sealed_passfile(operation)
            .map_err(|_| dump_unavailable())?;
        if pgtool::validate_sealed_passfile(&passfile).is_err() {
            drop(passfile);
            return Err(dump_unavailable());
        }

        let statement_ms = u64::try_from(remaining.whole_milliseconds()).unwrap_or(u64::MAX);
        if statement_ms == 0 {
            drop(passfile);
            return Err(dump_unavailable());
        }

        let mut command = Command::new(&self.config.binary_path);
        command
            .args([
                "--format=custom",
                "--compress=zstd:3",
                "--no-owner",
                "--no-privileges",
                "--no-tablespaces",
                "--no-password",
            ])
            .arg(format!("--host={}", pgtool::PINNED_PG_HOST))
            .arg(format!("--port={}", pgtool::PINNED_PG_PORT))
            .arg(format!("--username={PINNED_BACKUP_ROLE}"))
            .arg(format!("--dbname={}", pgtool::PINNED_PG_DATABASE))
            // SC-DEF-52: `central_runtime` is deliberately never granted
            // any privilege on this one table; pg_dump must skip it
            // rather than the role gaining access it was never meant
            // to have.
            .arg(format!(
                "--exclude-table={}",
                central_backup::backup::operation::RECOVERY_BOOTSTRAP_REGISTRATION_TABLE
            ))
            .env_clear()
            .envs([
                ("LC_ALL", "C"),
                ("TZ", "UTC"),
                ("PGPASSFILE", "/proc/self/fd/3"),
                ("PGCONNECT_TIMEOUT", "5"),
            ])
            .env(
                "PGAPPNAME",
                format!("central-backup-{}", operation.operation_id),
            )
            .env("PGOPTIONS", pgtool::pg_options(statement_ms))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        // ExtraFiles + fd 3: `pre_exec` dups the sealed descriptor onto
        // 3 inside the child. `passfile` stays alive through `spawn`
        // and is dropped right after — only the child's copy remains.
        crate::sys::audited::pg_tool_command(
            &mut command,
            passfile.as_raw_fd(),
            std::process::id(),
        );

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                drop(passfile);
                return Err(dump_unavailable());
            }
        };
        drop(passfile);

        let stdout = child.stdout.take().ok_or_else(dump_unavailable)?;

        let stream = PgDumpStream::new(child, stdout, Instant::now() + remaining_std);
        Ok(Box::new(stream))
    }
}

struct PgDumpInner {
    stdout: Option<ChildStdout>,
    reaper: Option<mpsc::Receiver<io::Result<ExitStatus>>>,
    pidfd: Option<std::os::fd::OwnedFd>,
    pid: i32,
    start: u64,
    eof: bool,
    settled: bool,
    close_err: Option<Failure>,
}

/// `pgDumpStream` — stdout plus owned child settlement. `Read` marks
/// EOF; `close` runs the bounded TERM→KILL→reap sequence. A watchdog
/// thread enforces the operation deadline even when the caller drops
/// the stream without closing: a lost adapter cannot strand a
/// `central_runtime` credential in a live child.
pub struct PgDumpStream {
    inner: Arc<Mutex<PgDumpInner>>,
}

impl PgDumpStream {
    pub(super) fn new(child: Child, stdout: ChildStdout, deadline: Instant) -> Self {
        let pid = i32::try_from(child.id()).unwrap_or_default();
        let start = pgtool::process_start_time(pid);
        let pidfd = Pid::from_raw(pid).and_then(|p| crate::sys::pidfd::open(p).ok());

        let (tx, rx) = mpsc::channel::<io::Result<ExitStatus>>();
        // `command.Wait()` equivalent: the reaper owns the only wait
        // call so settlement can enforce a finite TERM/KILL window
        // without abandoning the child.
        let mut reaped = child;
        thread::spawn(move || {
            let status = reaped.wait();
            let _ = tx.send(status);
        });

        let inner = Arc::new(Mutex::new(PgDumpInner {
            stdout: Some(stdout),
            reaper: Some(rx),
            pidfd,
            pid,
            start,
            eof: false,
            settled: false,
            close_err: None,
        }));

        // Deadline watchdog — Go's `ctx.Done()` path. If the caller
        // has already settled, this is a no-op; otherwise it forces
        // the same close sequence so the deadline kills the run.
        let watchdog = Arc::clone(&inner);
        thread::spawn(move || {
            let now = Instant::now();
            if deadline > now {
                thread::sleep(deadline - now);
            }
            Self::close_inner(&watchdog, true);
        });

        Self { inner }
    }

    /// `Close` — owns child settlement. On an early close it
    /// terminates the whole process group before reaping, so a
    /// repository failure cannot leave `pg_dump` or a descendant
    /// holding an offline permit or passfile descriptor.
    fn close_inner(inner: &Arc<Mutex<PgDumpInner>>, deadline_expired: bool) {
        let mut g = pgtool::lock_inner(inner);
        if g.settled {
            return;
        }
        g.settled = true;
        let reached_eof = g.eof;
        // Close the reader first — an early close turns into
        // EPIPE for a child still writing the archive pipe.
        drop(g.stdout.take());

        let Some(reaper) = g.reaper.take() else {
            g.close_err = Some(dump_unavailable());
            drop(g.pidfd.take());
            return;
        };

        // EOF is the expected completion point: give a child that
        // already closed its pipe bounded grace to exit normally;
        // an early close or expired deadline starts TERM
        // immediately.
        let mut outcome: Option<io::Result<ExitStatus>> = None;
        if reached_eof && !deadline_expired {
            outcome = pgtool::wait_timeout(&reaper, pgtool::CANCEL_GRACE);
        }
        if outcome.is_none() {
            pgtool::signal_pg_process(g.pid, g.pidfd.as_ref(), g.start, Signal::TERM);
            outcome = pgtool::wait_timeout(&reaper, pgtool::CANCEL_GRACE);
        }
        if outcome.is_none() {
            pgtool::signal_pg_process(g.pid, g.pidfd.as_ref(), g.start, Signal::KILL);
            outcome = pgtool::wait_timeout(&reaper, pgtool::KILL_WAIT);
        }
        drop(g.pidfd.take());

        g.close_err = match outcome {
            Some(Ok(status)) if status.success() && !deadline_expired => None,
            _ => Some(dump_unavailable()),
        };
    }
}

impl Read for PgDumpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut g = pgtool::lock_inner(&self.inner);
        let Some(stdout) = g.stdout.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pg dump stream closed",
            ));
        };
        let n = stdout.read(buf)?;
        if n == 0 && !buf.is_empty() {
            g.eof = true;
        }
        Ok(n)
    }
}

impl ReadClose for PgDumpStream {
    /// `Close` — reap first, then report. The reaper/wait errors and
    /// a non-zero exit both collapse to the one redacted failure.
    fn close(self: Box<Self>) -> Result<(), Failure> {
        Self::close_inner(&self.inner, false);
        let g = pgtool::lock_inner(&self.inner);
        match &g.close_err {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    use central_backup::backup::operation::new_backup_operation;
    use central_backup::domain::TargetIdentity;

    fn target() -> TargetIdentity {
        TargetIdentity {
            system_id: "sys-1".into(),
            database_oid: "16384".into(),
            database: "central".into(),
            config_hash: "cfg".into(),
            epoch: 1,
        }
    }

    fn dumping_operation(age: Duration) -> BackupOperation {
        let now = time::OffsetDateTime::now_utc();
        let mut op = new_backup_operation(
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            target(),
            now - time::Duration::seconds(2),
        )
        .expect("backup operation");
        op.phase = BackupPhase::Dumping;
        op.accepted_at = now - time::Duration::try_from(age).unwrap_or(time::Duration::ZERO);
        op
    }

    struct MemfdPassfile;
    impl SealedPassfileProvider for MemfdPassfile {
        fn open_sealed_passfile(&self, _operation: &BackupOperation) -> Result<File, Failure> {
            crate::sys::memfd::create_sealed(
                "pgpass",
                b"127.0.0.1:55432:central:central_runtime:redacted",
            )
            .map(File::from)
        }
    }

    fn fake_tool(body: &str) -> (std::path::PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("central-pg-tool-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("test dir");
        let path = dir.join("pg_dump");
        let mut f = File::create(&path).expect("script");
        writeln!(f, "#!/bin/sh").expect("script");
        f.write_all(body.as_bytes()).expect("script");
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        (dir, path)
    }

    fn config(path: PathBuf) -> PgDumpConfig {
        PgDumpConfig {
            binary_path: path,
            version: PINNED_PG_DUMP_VERSION.to_owned(),
            max_elapsed: Duration::from_secs(3600),
        }
    }

    #[test]
    fn config_rejects_caller_shaped_values() {
        let mut c = config(PathBuf::from("/usr/bin/pg_dump"));
        c.binary_path = PathBuf::from("pg_dump");
        assert!(c.validate().is_err(), "relative path must refuse");
        c.binary_path = PathBuf::from("/usr/bin/pg_dump");
        c.version = "16.15".into();
        assert!(c.validate().is_err(), "version drift must refuse");
        c.version = PINNED_PG_DUMP_VERSION.into();
        c.max_elapsed = Duration::ZERO;
        assert!(c.validate().is_err(), "zero budget must refuse");
        c.max_elapsed = Duration::from_secs(9 * 3600);
        assert!(c.validate().is_err(), "over-deadline budget must refuse");
    }

    #[test]
    fn sealed_passfile_shape() {
        let sealed = crate::sys::memfd::create_sealed("pgpass", b"host=x").expect("sealed");
        assert!(pgtool::validate_sealed_passfile(&sealed).is_ok());

        let dir = std::env::temp_dir().join(format!("central-pg-tool-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("dir");
        let plain = File::create(dir.join("passfile")).expect("plain file");
        assert!(
            pgtool::validate_sealed_passfile(&plain).is_err(),
            "an unsealed regular file must refuse"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn process_start_time_of_self_is_nonzero() {
        assert_ne!(0, pgtool::process_start_time(std::process::id() as i32));
        assert_eq!(0, pgtool::process_start_time(-1));
    }

    #[test]
    fn start_dump_refuses_wrong_phase() {
        let (dir, path) = fake_tool("printf x");
        let dumper = PgDump::new(config(path), Box::new(MemfdPassfile)).expect("dumper");
        let mut op = dumping_operation(Duration::ZERO);
        op.phase = BackupPhase::Admitted;
        assert!(
            dumper.start_dump(&op).is_err(),
            "only dumping admits a dump"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn start_dump_refuses_exhausted_budget() {
        let (dir, path) = fake_tool("printf x");
        let dumper = PgDump::new(config(path), Box::new(MemfdPassfile)).expect("dumper");
        // max_elapsed 3600 s; accepted_at ~3595 s ago leaves < 30 s.
        let op = dumping_operation(Duration::from_secs(3595));
        assert!(dumper.start_dump(&op).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dump_streams_bytes_and_reaps_cleanly() {
        let (dir, path) = fake_tool("test -r /proc/self/fd/3 || exit 9\nprintf 'dump-bytes'");
        let dumper = PgDump::new(config(path), Box::new(MemfdPassfile)).expect("dumper");
        let op = dumping_operation(Duration::ZERO);
        let mut stream = dumper.start_dump(&op).expect("stream");
        let mut body = Vec::new();
        stream.read_to_end(&mut body).expect("read");
        assert_eq!(b"dump-bytes", body.as_slice());
        assert!(stream.close().is_ok(), "clean EOF close must succeed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn early_close_terminates_process_group() {
        let (dir, path) = fake_tool("sleep 60");
        let dumper = PgDump::new(config(path), Box::new(MemfdPassfile)).expect("dumper");
        let op = dumping_operation(Duration::ZERO);
        let stream = dumper.start_dump(&op).expect("stream");
        let started = Instant::now();
        assert!(
            stream.close().is_err(),
            "closing a still-running dump is a redacted process failure"
        );
        assert!(started.elapsed() < Duration::from_secs(15));
        std::fs::remove_dir_all(&dir).ok();
    }
}
