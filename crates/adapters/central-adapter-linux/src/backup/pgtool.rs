//! Shared internals for the pinned `pg_dump`/`pg_restore` adapters.
//!
//! Everything here is redacted-failure discipline: the stable code is
//! the only detail a caller may classify on; stderr, paths, commands,
//! and target values never cross the capability boundary.

use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::process::ExitStatus;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use central_foundation::failure::Failure;
use rustix::fs::{FileType, SealFlags, fcntl_get_seals, fstat};
use rustix::process::{Pid, Signal, kill_process_group};

use crate::sys::pidfd;

/// `pinnedPGHost` — loopback only; no transport ever leaves the host.
pub(super) const PINNED_PG_HOST: &str = "127.0.0.1";
/// `pinnedPGPort` — the trusted PostgreSQL endpoint port.
pub(super) const PINNED_PG_PORT: u16 = 55432;
/// `pinnedPGDatabase` — the one database these tools may address.
pub(super) const PINNED_PG_DATABASE: &str = "central";

/// `minimumDumpBudget` — the engine never starts a dump/restore it
/// cannot let finish: 30 s of guaranteed remaining budget, from
/// upstream `pgdump_linux.go`/`pgrestore_linux.go`.
pub(super) const MINIMUM_TOOL_BUDGET: Duration = Duration::from_secs(30);
/// `dumpCancelGrace`/`restoreCancelGrace` — TERM-to-KILL window.
pub(super) const CANCEL_GRACE: Duration = Duration::from_secs(5);
/// `dumpKillWait`/`restoreKillWait` — KILL settle window.
pub(super) const KILL_WAIT: Duration = Duration::from_secs(1);
/// `maximumPassfileBytes` — `secretbootstrap.MaxSecretBytes` mirror.
const MAXIMUM_PASSFILE_BYTES: u64 = 64 * 1024;

/// `PGOPTIONS` pins statement, lock, and idle-in-transaction timeouts so
/// a stalled target cannot pin the tool forever; `statement_timeout`
/// follows the operation's remaining budget.
pub(super) fn pg_options(statement_ms: u64) -> String {
    format!(
        "-c statement_timeout={statement_ms} -c lock_timeout=30000 -c idle_in_transaction_session_timeout=60000"
    )
}

/// `waitPGDump` — one bounded receive on the reaper channel; `None`
/// means the timeout expired with the child still running.
pub(super) fn wait_timeout(
    reaper: &Receiver<io::Result<ExitStatus>>,
    timeout: Duration,
) -> Option<io::Result<ExitStatus>> {
    if timeout.is_zero() {
        reaper.try_recv().ok()
    } else {
        reaper.recv_timeout(timeout).ok()
    }
}

/// `signalPGProcess` — pidfd-first signal plus the process-group signal
/// that settles descendants which inherited the tool's pipe. The
/// `/proc` start-time check prevents a reused PID from being targeted
/// when the signal races with exit or pidfd is unavailable.
pub(super) fn signal_pg_process(pid: i32, pidfd: Option<&OwnedFd>, start: u64, sig: Signal) {
    if pid <= 0 {
        return;
    }
    if let Some(fd) = pidfd {
        let _ = pidfd::send_signal(fd, sig);
    }
    if start != 0
        && process_start_time(pid) == start
        && let Some(pgid) = Pid::from_raw(pid)
    {
        let _ = kill_process_group(pgid, sig);
    }
}

/// `processStartTime` — field 22 of `/proc/<pid>/stat`. The `comm`
/// field may contain spaces and parentheses, so parsing starts after
/// the final `)`; `starttime` is then index 19. Returns 0 when the
/// process or the field cannot be read (fail closed).
pub(super) fn process_start_time(pid: i32) -> u64 {
    let Ok(data) = std::fs::read(format!("/proc/{pid}/stat")) else {
        return 0;
    };
    let Some(close_paren) = data.iter().rposition(|b| *b == b')') else {
        return 0;
    };
    if close_paren + 2 >= data.len() {
        return 0;
    }
    let fields: Vec<&str> = std::str::from_utf8(&data[close_paren + 2..])
        .unwrap_or("")
        .split_ascii_whitespace()
        .collect();
    if fields.len() <= 19 {
        return 0;
    }
    fields[19].parse::<u64>().unwrap_or(0)
}

/// `validateSealedPassfile` — the fd-3 contract: full seal set
/// (`SEAL|SHRINK|GROW|WRITE`), regular file, non-empty and at most
/// 64 KiB. Ownership/transport checks belong to the memfd handoff
/// boundary upstream of this point; here the tool proves only that
/// the descriptor it is about to leak to `execve` is immutable
/// evidence of broker credential release.
pub(super) fn validate_sealed_passfile<Fd: AsFd>(fd: &Fd) -> Result<(), Failure> {
    let seals = fcntl_get_seals(fd).map_err(|_| pg_tool_unavailable())?;
    if !seals.contains(
        SealFlags::SEAL
            .union(SealFlags::SHRINK)
            .union(SealFlags::GROW)
            .union(SealFlags::WRITE),
    ) {
        return Err(pg_tool_unavailable());
    }
    let stat = fstat(fd).map_err(|_| pg_tool_unavailable())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_size <= 0
        || u64::try_from(stat.st_size).unwrap_or(u64::MAX) > MAXIMUM_PASSFILE_BYTES
    {
        return Err(pg_tool_unavailable());
    }
    Ok(())
}

/// `io.ReadAll(io.LimitReader(passfile, max+1))` plus the NUL refusal —
/// the one-shot bounded read of a sealed credential descriptor for the
/// runtime-connection parse upstream performs inside
/// `openRuntimeConnectionFromSealedPassfile`. The read starts at the
/// descriptor's current offset exactly like upstream's `*os.File`;
/// callers own [`zeroize::Zeroize`]-style wiping of the returned bytes.
///
/// # Errors
/// `backup_pg_tool_unavailable` on any seal/shape violation, a read
/// failure, an empty value, a value over 64 KiB, or a NUL byte.
pub fn read_sealed_passfile_value<Fd: AsFd>(fd: &Fd) -> Result<Vec<u8>, Failure> {
    validate_sealed_passfile(fd)?;
    let mut value = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    loop {
        let n = rustix::io::read(fd, &mut buf).map_err(|_| pg_tool_unavailable())?;
        if n == 0 {
            break;
        }
        value.extend_from_slice(&buf[..n]);
        if u64::try_from(value.len()).unwrap_or(u64::MAX) > MAXIMUM_PASSFILE_BYTES {
            return Err(pg_tool_unavailable());
        }
    }
    if value.is_empty() || value.contains(&0) {
        return Err(pg_tool_unavailable());
    }
    Ok(value)
}

/// The one redacted process-boundary failure. Callers may classify on
/// this stable code only — never on stderr or a locator.
fn pg_tool_unavailable() -> Failure {
    Failure::unavailable(
        "backup_pg_tool_unavailable",
        "pg tool process boundary unavailable",
    )
}

/// Shared lock helper — a poisoned mutex is a bug, not a retryable
/// failure; recover the guard so the settle path still runs.
pub(super) fn lock_inner<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
