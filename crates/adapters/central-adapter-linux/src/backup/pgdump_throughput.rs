//! `pgdump_throughput_linux.go` — the pinned `pg_dump` invocation
//! against the one deterministic disposable probe database. The
//! provider, not this adapter's caller, derives both database and
//! credential from the probe operation; the fd-3 sealed passfile and
//! process-group death boundaries are identical to [`super::pg_dump`].
//!
//! Throughput probes get their own application name, database name,
//! and `MaxElapsed`-bounded statement timeout — but the same host,
//! port, role, env whitelist, and sealed-credential handoff.

#![forbid(unsafe_code)]

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::process::{Command, Stdio};
use std::time::Instant;

use central_backup::backup::capacity::MAXIMUM_THROUGHPUT_PROBE_ELAPSED;
use central_backup::port::ReadClose;
use central_foundation::failure::Failure;
use uuid::Uuid;

use super::pg_dump::{PINNED_BACKUP_ROLE, PgDumpConfig, PgDumpStream};
use super::pgtool;
use super::throughput_probe::ThroughputProbeDumpSource;

/// `ErrPGDumpThroughputProbe` — closed, locator-free probe
/// refusal.
fn probe_dump_unavailable() -> Failure {
    Failure::unavailable(
        "pg_dump_throughput_probe",
        "recovery throughput pg_dump unavailable",
    )
}

/// `ThroughputProbePassfileProvider` — returns a broker-derived
/// sealed passfile for the one deterministic disposable database.
/// The provider, not this adapter's caller, derives both database
/// and credential from the probe operation.
pub trait ThroughputProbePassfileProvider: Send + Sync {
    /// `OpenThroughputProbePassfile`.
    fn open_throughput_probe_passfile(&self, operation_id: Uuid) -> Result<File, Failure>;
}

/// `PGDumpThroughputProbe` — implements
/// [`ThroughputProbeDumpSource`].
pub struct PgDumpThroughputProbe {
    config: PgDumpConfig,
    passfiles: Box<dyn ThroughputProbePassfileProvider>,
}

impl PgDumpThroughputProbe {
    /// `NewPGDumpThroughputProbe` — a valid pinned config whose
    /// elapsed budget fits inside
    /// [`MAXIMUM_THROUGHPUT_PROBE_ELAPSED`], plus a passfile provider.
    pub fn new(
        config: PgDumpConfig,
        passfiles: Box<dyn ThroughputProbePassfileProvider>,
    ) -> Result<Self, Failure> {
        config.validate()?;
        if config.max_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED.unsigned_abs() {
            return Err(probe_dump_unavailable());
        }
        Ok(Self { config, passfiles })
    }
}

impl ThroughputProbeDumpSource for PgDumpThroughputProbe {
    /// `OpenThroughputProbeDump` — starts exactly one pinned
    /// custom-format `pg_dump` on the probe database. The returned
    /// stream is stdout only; `close` reaps the child.
    fn open_throughput_probe_dump(
        &self,
        operation_id: Uuid,
    ) -> Result<Box<dyn ReadClose>, Failure> {
        if self.config.validate().is_err()
            || self.config.max_elapsed > MAXIMUM_THROUGHPUT_PROBE_ELAPSED.unsigned_abs()
            || operation_id.is_nil()
            || operation_id.get_version_num() != 7
        {
            return Err(probe_dump_unavailable());
        }
        let passfile = self
            .passfiles
            .open_throughput_probe_passfile(operation_id)
            .map_err(|_| probe_dump_unavailable())?;
        if pgtool::validate_sealed_passfile(&passfile).is_err() {
            drop(passfile);
            return Err(probe_dump_unavailable());
        }
        let database = throughput_probe_database_name(operation_id);
        let statement_ms = u64::try_from(self.config.max_elapsed.as_millis()).unwrap_or(u64::MAX);
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
            .arg(format!("--dbname={database}"))
            .env_clear()
            .envs([
                ("LC_ALL", "C"),
                ("TZ", "UTC"),
                ("PGPASSFILE", "/proc/self/fd/3"),
                ("PGCONNECT_TIMEOUT", "5"),
            ])
            .env(
                "PGAPPNAME",
                format!("central-throughput-probe-{operation_id}"),
            )
            .env("PGOPTIONS", pgtool::pg_options(statement_ms))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        crate::sys::audited::pg_tool_command(
            &mut command,
            passfile.as_raw_fd(),
            std::process::id(),
        );

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                drop(passfile);
                return Err(probe_dump_unavailable());
            }
        };
        drop(passfile);

        let stdout = child.stdout.take().ok_or_else(probe_dump_unavailable)?;
        let stream = PgDumpStream::new(child, stdout, Instant::now() + self.config.max_elapsed);
        Ok(Box::new(stream))
    }
}

/// `throughputProbeDatabaseName` — `central_probe_<uuid>`, dashes
/// removed, exactly the disposable database the helper provisions
/// per operation.
fn throughput_probe_database_name(operation_id: Uuid) -> String {
    format!("central_probe_{}", operation_id.simple())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn config(elapsed: Duration) -> PgDumpConfig {
        PgDumpConfig {
            binary_path: PathBuf::from("/usr/bin/pg_dump"),
            version: "16.14".into(),
            max_elapsed: elapsed,
        }
    }

    struct FakePassfiles {
        sealed: AtomicBool,
    }
    impl ThroughputProbePassfileProvider for FakePassfiles {
        fn open_throughput_probe_passfile(&self, _operation_id: Uuid) -> Result<File, Failure> {
            if self.sealed.load(Ordering::SeqCst) {
                crate::sys::memfd::create_sealed(
                    "pgpass",
                    b"127.0.0.1:55432:central:central_runtime:redacted",
                )
                .map(File::from)
            } else {
                File::open("/dev/null").map_err(|_| probe_dump_unavailable())
            }
        }
    }

    #[test]
    fn config_requires_valid_pinned_shape_and_probe_budget() {
        // Budget beyond the five-minute probe window refuses.
        assert!(
            PgDumpThroughputProbe::new(
                config(Duration::from_secs(600)),
                Box::new(FakePassfiles {
                    sealed: AtomicBool::new(true),
                }),
            )
            .is_err()
        );
        // Wrong tool version refuses via the pinned config.
        let mut bad = config(Duration::from_secs(60));
        bad.version = "15.0".into();
        assert!(
            PgDumpThroughputProbe::new(
                bad,
                Box::new(FakePassfiles {
                    sealed: AtomicBool::new(true),
                }),
            )
            .is_err()
        );
        // The pinned shape assembles.
        assert!(
            PgDumpThroughputProbe::new(
                config(Duration::from_secs(120)),
                Box::new(FakePassfiles {
                    sealed: AtomicBool::new(true),
                }),
            )
            .is_ok()
        );
    }

    #[test]
    fn probe_dump_refuses_bad_identity_and_unsealed_passfile() {
        let probe = PgDumpThroughputProbe::new(
            config(Duration::from_secs(120)),
            Box::new(FakePassfiles {
                sealed: AtomicBool::new(true),
            }),
        )
        .unwrap();
        assert!(probe.open_throughput_probe_dump(Uuid::nil()).is_err());
        assert!(probe.open_throughput_probe_dump(Uuid::new_v4()).is_err());
        // An unsealed passfile refuses before spawn.
        let unsealed = PgDumpThroughputProbe::new(
            config(Duration::from_secs(120)),
            Box::new(FakePassfiles {
                sealed: AtomicBool::new(false),
            }),
        )
        .unwrap();
        assert!(unsealed.open_throughput_probe_dump(Uuid::now_v7()).is_err());
    }

    #[test]
    fn probe_database_name_is_deterministic_per_operation() {
        let id = Uuid::now_v7();
        let name = throughput_probe_database_name(id);
        assert_eq!(name, format!("central_probe_{}", id.simple()));
        assert!(!name.contains('-'));
        assert_ne!(name, throughput_probe_database_name(Uuid::now_v7()));
    }
}
