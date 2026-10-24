//! The production [`GroupSignals`] — the audited `kill(2)` boundary
//! upstream's `localexec` package carries as its package-level
//! `groupAlive`/`sendSignal` helpers (injected there via
//! `export_test.go`). Both run through rustix's `kill` wrappers; no
//! `unsafe` appears here.
//!
//! - `group_alive` → `kill(-pgid, 0)` — [`test_kill_process_group`]:
//!   `Ok` and `EPERM` both mean the group exists (EPERM is "exists but
//!   owned by someone else", which still counts as alive). `ESRCH` —
//!   or any unexpected error — is treated as gone; a probe that cannot
//!   decide must not keep a scope alive.
//! - `send_signal` → `kill(-pgid, sig)` —
//!   [`kill_process_group`]: `ESRCH` (the group already ended) is not
//!   an error to the kill ladder. Every other error propagates.

use central_adapter_harness::localexec::{GroupSignals, Signal};
use central_foundation::failure::Failure;
use rustix::io::Errno;
use rustix::process::{Pid, kill_process_group, test_kill_process_group};

/// `LinuxGroupSignals` — the production process-group signal source
/// for `LocalExec` (the dev-gated launcher only; the production path
/// kills by cgroup through the launcher daemon).
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxGroupSignals;

impl LinuxGroupSignals {
    /// The unit struct's only constructor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// `pid` — the positive `Pid` `pgid` names, or the refusal a
/// non-positive group id maps to. `pgid` is an `i64` on the port side
/// (upstream's `int`-sized value); values outside `RawPid` range are
/// invalid, never truncated.
fn group_pid(pgid: i64) -> Result<Pid, Failure> {
    let invalid = || {
        Failure::invalid(
            "localexec_invalid_pgid",
            format!("process group id {pgid} is not a positive pid"),
        )
    };
    let raw = i32::try_from(pgid).map_err(|_| invalid())?;
    if raw <= 0 {
        return Err(invalid());
    }
    Pid::from_raw(raw).ok_or_else(invalid)
}

/// `signal` — the port's two-value vocabulary to the kernel's.
fn to_signal(sig: Signal) -> rustix::process::Signal {
    match sig {
        Signal::Term => rustix::process::Signal::TERM,
        Signal::Kill => rustix::process::Signal::KILL,
    }
}

impl GroupSignals for LinuxGroupSignals {
    /// `groupAlive` — `kill(-pgid, 0)`: `Ok` or `EPERM` is alive; a
    /// non-positive `pgid` or any other error is gone.
    fn group_alive(&self, pgid: i64) -> bool {
        let Some(pid) = group_pid(pgid).ok() else {
            return false;
        };
        match test_kill_process_group(pid) {
            Ok(()) | Err(Errno::PERM) => true,
            Err(_) => false,
        }
    }

    /// `sendSignal` — `kill(-pgid, sig)`; `ESRCH` (already gone) is
    /// not an error to a caller of the kill ladder.
    fn send_signal(&self, pgid: i64, sig: Signal) -> Result<(), Failure> {
        let pid = group_pid(pgid)?;
        match kill_process_group(pid, to_signal(sig)) {
            Ok(()) | Err(Errno::SRCH) => Ok(()),
            Err(e) => Err(Failure::internal(
                "localexec_signal_failed",
                format!("kill(-{pgid}, {}): {e}", sig_name(sig)),
            )),
        }
    }
}

fn sig_name(sig: Signal) -> &'static str {
    match sig {
        Signal::Term => "SIGTERM",
        Signal::Kill => "SIGKILL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The caller's own process group is a group that always exists,
    /// so `group_alive` proves both the probe syscall and the positive
    /// `pgid` mapping without needing a spawned child.
    #[test]
    fn group_alive_reports_own_group() {
        let pgid = i64::from(rustix::process::getpid().as_raw_nonzero().get());
        let pgid = i64::from(
            rustix::process::getpgid(Some(rustix::process::getpid()))
                .unwrap_or_else(|_| Pid::from_raw(pgid as i32).unwrap_or(Pid::INIT))
                .as_raw_nonzero()
                .get(),
        );
        assert!(LinuxGroupSignals.group_alive(pgid));
    }

    /// A group id in the unallocatable range probes gone — `ESRCH`
    /// maps to `false`, and `send_signal` treats it as a no-op success
    /// exactly the way upstream's kill ladder expects.
    #[test]
    fn absent_group_is_gone_and_signal_is_noop() {
        // `i32::MAX` can never be a live pgid alongside the test's own
        // pid space (pid_max is far below it on every supported host).
        let pgid = i64::from(i32::MAX);
        assert!(!LinuxGroupSignals.group_alive(pgid));
        LinuxGroupSignals
            .send_signal(pgid, Signal::Term)
            .expect("ESRCH is a kill-ladder no-op");
        LinuxGroupSignals
            .send_signal(pgid, Signal::Kill)
            .expect("ESRCH is a kill-ladder no-op");
    }

    /// Non-positive group ids refuse — never mapped onto a raw pid.
    #[test]
    fn invalid_group_ids_refuse() {
        for pgid in [0, -1, -100, i64::MIN, i64::from(i32::MAX) + 1] {
            assert!(!LinuxGroupSignals.group_alive(pgid));
            let err = LinuxGroupSignals
                .send_signal(pgid, Signal::Term)
                .expect_err("non-positive pgid must refuse");
            assert_eq!(err.code(), "localexec_invalid_pgid");
        }
    }
}
