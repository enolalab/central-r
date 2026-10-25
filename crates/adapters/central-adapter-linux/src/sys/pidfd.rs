//! `pidfd` — a stable descriptor handle on a process, immune to
//! PID-reuse confusion, the handle the broker pins alongside
//! `SO_PEERCRED` (upstream's `pidfd_open` liveness model).
//!
//! - [`open`] wraps `pidfd_open(2)` — `ESRCH` when the process is
//!   already gone.
//! - [`alive`] polls the descriptor: a live process is not readable; a
//!   dead one becomes `POLLIN`-readable and stays so.
//! - [`is_pidfd`] is the descriptor-kind check upstream applies to
//!   SCM_RIGHTS'd handles: `fstatfs` must report the pidfs.

use std::os::fd::{AsFd, OwnedFd};

use central_foundation::failure::Failure;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{Timespec, fstatfs};
use rustix::io::Errno;
use rustix::process::{Pid, PidfdFlags, pidfd_open};

/// `PID_FS_MAGIC` — `fstatfs.f_type` for a pidfd
/// (`include/uapi/linux/magic.h`: `#define PID_FS_MAGIC 0x50494446`).
const PID_FS_MAGIC: rustix::fs::FsWord = 0x5049_4446;

fn os_failure(step: &str, e: Errno) -> Failure {
    Failure::internal("sys_pidfd_os", format!("{step}: {e}"))
}

fn invalid(msg: impl Into<String>) -> Failure {
    Failure::invalid("sys_pidfd_invalid", msg.into())
}

/// `pidfd_open(pid, 0)` — a descriptor handle on `pid`. `ESRCH`
/// means the process was already gone at open time.
///
/// # Errors
/// `sys_pidfd_os` on the syscall failure.
pub fn open(pid: Pid) -> Result<OwnedFd, Failure> {
    pidfd_open(pid, PidfdFlags::empty()).map_err(|e| os_failure("pidfd_open", e))
}

/// `is_pidfd` — the descriptor-kind check upstream's
/// `validateProvisionerClientFD` applies to SCM_RIGHTS'd handles,
/// `fstatfs` form: the fd's filesystem must be the pidfs.
///
/// # Errors
/// `sys_pidfd_invalid` when the descriptor is not a pidfd;
/// `sys_pidfd_os` when `fstatfs` fails.
pub fn is_pidfd<Fd: AsFd>(fd: Fd) -> Result<(), Failure> {
    let fs = fstatfs(fd).map_err(|e| os_failure("fstatfs", e))?;
    if fs.f_type != PID_FS_MAGIC {
        return Err(invalid(format!(
            "fd is not a pidfd (fs type {:#x})",
            fs.f_type
        )));
    }
    Ok(())
}

/// Liveness the pidfd way: a dead process's pidfd reports `POLLIN`
/// (the kernel's "exit happened" edge stays level-triggered), a live
/// one does not. Zero-timeout `poll`.
///
/// Upstream checks liveness via `PidfdSendSignal(fd, 0)` /
/// `waitid(P_PIDFD)` (`protocol_linux.go`, `client_linux.go`,
/// `settle.go`) — this poll form is equivalent-or-stronger: it polls
/// the descriptor, never `kill(pid, 0)`, so PID reuse can never make a
/// stale pid look alive.
///
/// # Errors
/// `sys_pidfd_os` on the `poll` failure.
pub fn alive<Fd: AsFd>(pidfd: Fd) -> Result<bool, Failure> {
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    const ZERO: Timespec = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    poll(&mut fds, Some(&ZERO)).map_err(|e| os_failure("poll", e))?;
    let revents = fds[0].revents();
    // POLLIN = the process exited. POLLERR counts too — a torn-down
    // descriptor is not "alive".
    Ok(!revents.intersects(PollFlags::IN | PollFlags::ERR))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pidfd on our own process: opens, is a pidfd, reads alive.
    #[test]
    fn pidfd_on_self() {
        let fd = open(rustix::process::getpid()).expect("pidfd_open self");
        is_pidfd(&fd).expect("is_pidfd");
        assert!(alive(&fd).expect("alive"));
    }

    /// A pidfd outlives its process: after the child exits and is
    /// reaped, the *same descriptor* reports dead — the property
    /// `kill(pid, 0)` cannot give once the pid is recycled.
    #[test]
    fn pidfd_reports_death() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn child");
        let raw = i32::try_from(child.id()).expect("child pid");
        let pid = Pid::from_raw(raw).expect("nonzero pid");
        let fd = open(pid).expect("pidfd_open child");
        is_pidfd(&fd).expect("is_pidfd");
        child.wait().expect("reap child");

        // The exit event is level-triggered — a single zero-timeout
        // poll sees it, no race.
        assert!(!alive(&fd).expect("dead check"));
    }

    /// A non-pidfd descriptor is refused — the SCM_RIGHTS shape
    /// check (`fd is not a pidfd`).
    #[test]
    fn is_pidfd_rejects_other_fds() {
        let (a, _b) = rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        )
        .expect("socketpair");
        let err = is_pidfd(&a).unwrap_err();
        assert_eq!(err.code(), "sys_pidfd_invalid");
        assert!(err.message().contains("not a pidfd"));
    }

    /// `pidfd_open` on a pid that does not exist is `ESRCH` — the
    /// "already gone at open time" refusal.
    #[test]
    fn open_rejects_gone_pid() {
        // Pid 4_000_000 is above the default pid_max and certainly
        // not allocated.
        let err = open(Pid::from_raw(4_000_000).expect("pid")).unwrap_err();
        assert_eq!(err.code(), "sys_pidfd_os");
    }
}
