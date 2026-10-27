//! Audited syscall boundary (workflow §5.2).
//!
//! Every `unsafe` of this binary lives behind a named safe wrapper
//! here — the sites rustix 1.1 has no safe API for: `fork`/`execve`,
//! `dup2`/`dup3`/`F_DUPFD_CLOEXEC` to fixed descriptor numbers,
//! `close_range`, `fcntl` `F_GETFL`/`F_SETFD`, `setgroups`/`setuid`/
//! `setgid`, the `prctl` pair (`PR_SET_PDEATHSIG`,
//! `PR_SET_CHILD_SUBREAPER`), signal-handler install, `_exit`,
//! `waitpid` on raw child pids, `kill`/`killpg` and the ESRCH probe,
//! a raw `close` whose error is observed, `setsid`, and `pause`. The
//! raw-fd ownership bridges ([`borrow`], [`dupfd_cloexec`]) are here
//! too so the rest of the crate stays free of `unsafe` entirely.
//! `SO_PEERCRED`, `SCM_RIGHTS`, `pidfd_open` and `pidfd_send_signal`
//! themselves live in the shared audited site —
//! `central_adapter_linux::sys` — which this crate calls rather than
//! re-opening.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

use rustix::io::Errno;

/// The result of a successful [`fork`].
pub enum Fork {
    /// In the parent: the child's pid.
    Parent(i32),
    /// In the child.
    Child,
}

/// `fork(2)`. The child must run only the pure-syscall path and end in
/// [`exit`] or [`execve`] — the caller guarantees it (the worker
/// launch path never returns to Rust-managed state; the monitor path
/// is single-threaded Rust ending in [`exit`], like
/// `central-harness-launcherd`'s monitor).
pub fn fork() -> Result<Fork, Errno> {
    // SAFETY: plain fork; the child paths are documented above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        Err(last_errno())
    } else if pid == 0 {
        Ok(Fork::Child)
    } else {
        Ok(Fork::Parent(pid))
    }
}

/// `execve(2)` — never returns on success.
pub fn execve(
    path: &std::ffi::CStr,
    argv: &[*const libc::c_char],
    envp: &[*const libc::c_char],
) -> Errno {
    // SAFETY: the caller guarantees `argv`/`envp` are NULL-terminated
    // pointer arrays to NUL-terminated strings; they are built as such
    // in session.rs right before this call.
    unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    last_errno()
}

/// `_exit(2)` — the only way a forked child ends (no atexit, no flush).
pub fn exit(code: i32) -> ! {
    // SAFETY: immediate termination; always sound.
    unsafe { libc::_exit(code) }
}

/// The current `errno` value after a libc call reported -1.
pub fn last_errno() -> Errno {
    Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::INVAL)
}

/// `close_range(first, ~0U, 0)`, with the upstream descriptor-loop
/// fallback for kernels without it (upstream `close_from`).
pub fn close_from(first: RawFd) {
    // SAFETY: first is a valid base; closing descriptors is always safe.
    if unsafe { libc::syscall(libc::SYS_close_range, first, !0u32, 0) } == 0 {
        return;
    }
    for fd in first..65536 {
        // SAFETY: closing a possibly-open descriptor number is harmless.
        unsafe { libc::close(fd) };
    }
}

/// `dup3(old, new, flags)` into a fixed descriptor number. The launch
/// path uses `flags = 0` for the descriptors that must survive `exec`
/// (worker FD3/FD4/FD5) and `O_CLOEXEC` for the ones that must not
/// (worker FD6 diagnostics, the monitor's FD3..FD7 channels).
pub fn dup3(old: RawFd, new: RawFd, cloexec: bool) -> Result<(), Errno> {
    let flags = if cloexec { libc::O_CLOEXEC } else { 0 };
    // SAFETY: plain descriptor numbers; the caller drops the old one.
    if unsafe { libc::dup3(old, new, flags) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `dup2(old, new)` into a fixed descriptor number.
pub fn dup2(old: RawFd, new: RawFd) -> Result<(), Errno> {
    // SAFETY: plain descriptor numbers; the caller drops the old one.
    if unsafe { libc::dup2(old, new) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `fcntl(fd, F_DUPFD_CLOEXEC, min)` — the collision-safe source dup
/// upstream runs before `dup3` onto the fixed child descriptors, and
/// the systemd `F_DUPFD_CLOEXEC` activation dup.
pub fn dupfd_cloexec(fd: RawFd, min: RawFd) -> Result<OwnedFd, Errno> {
    // SAFETY: fcntl on an open descriptor; the result is owned.
    let r = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
    if r < 0 {
        return Err(last_errno());
    }
    // SAFETY: `r` is a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// `fcntl(fd, F_GETFL)` — the repository descriptor's status flags
/// (`O_ACCMODE`/`O_PATH`), upstream `validate_repository_fd`.
pub fn getfl(fd: RawFd) -> Result<i32, Errno> {
    // SAFETY: fcntl on a possibly-open descriptor number.
    let r = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if r < 0 {
        return Err(last_errno());
    }
    Ok(r)
}

/// `close(2)` on a raw fd — a no-op on an already-closed number.
pub fn close(fd: RawFd) {
    // SAFETY: closing a descriptor number is harmless.
    unsafe { libc::close(fd) };
}

/// `close(2)` whose return is observed — upstream's commit path keys
/// the ACK on `close(evidence_fd) == 0`, so the close must not hide an
/// error behind `OwnedFd`'s infallible drop.
pub fn close_checked(fd: RawFd) -> Result<(), Errno> {
    // SAFETY: closing a descriptor number is harmless.
    if unsafe { libc::close(fd) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `open(path, O_RDWR | O_CLOEXEC)` inside the forked child for
/// `/dev/null` — returns the raw descriptor.
pub fn open_rdwr_cloexec(path: &std::ffi::CStr) -> Result<RawFd, Errno> {
    // SAFETY: plain open of a NUL-terminated path.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_errno());
    }
    Ok(fd)
}

/// `write(2)` on a raw fd — the child's pre-exec error report.
/// Returns bytes written.
pub fn write_raw(fd: RawFd, buf: &[u8]) -> usize {
    // SAFETY: `buf` is readable for its length; a failed write is a
    // negative return the caller ignores exactly like upstream.
    unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) as usize }
}

/// `setgroups(0, NULL)` — drop every supplementary group before the
/// identity switch. Skipped entirely under the test-peer knob, exactly
/// like upstream's `#ifndef CENTRAL_BACKUP_LAUNCHER_TEST_PEER_UID` — a
/// non-root test daemon cannot call it.
pub fn set_groups_none() -> Result<(), Errno> {
    // SAFETY: empty group list; NULL is the documented form.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `setgid(2)` then `setuid(2)` in upstream's order.
pub fn drop_to(uid: u32, gid: u32) -> Result<(), Errno> {
    // SAFETY: plain id arguments.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: plain id argument.
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `prctl(PR_SET_PDEATHSIG, sig)` — the worker dies with its monitor
/// (SIGKILL), the monitor shuts down with the daemon (SIGTERM).
pub fn set_pdeathsig(sig: i32) -> Result<(), Errno> {
    // SAFETY: a flag prctl; no memory is shared.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig, 0, 0, 0) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `prctl(PR_SET_CHILD_SUBREAPER, 1)` — the daemon and each per-launch
/// monitor reap the detached descendants of their trees.
pub fn set_child_subreaper() -> Result<(), Errno> {
    // SAFETY: a flag prctl; no memory is shared.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `setsid(2)` — the worker's own session and process group, so the
/// monitor's `kill(-pid, SIGKILL)` covers the whole worker group.
pub fn setsid() -> Result<(), Errno> {
    // SAFETY: no arguments; a session switch is always sound here.
    if unsafe { libc::setsid() } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `pause(2)` — the test fixture's hung worker and detached
/// descendant block on it.
#[cfg(feature = "test-build")]
#[allow(dead_code)] // used only by `cbl-test-worker`
pub fn pause() {
    // SAFETY: blocking for a signal is always sound.
    unsafe { libc::pause() };
}

/// `waitpid(pid, &mut status, flags)` on a raw child pid, retrying on
/// `EINTR`. Returns `Some(status)` when the pid was reaped, `None` for
/// a live child under `WNOHANG`.
pub fn wait_pid(pid: i32, no_hang: bool) -> Result<Option<i32>, Errno> {
    let flags = if no_hang { libc::WNOHANG } else { 0 };
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `status` is a live int; `pid` is our child.
        let r = unsafe { libc::waitpid(pid, &mut status, flags) };
        if r == pid {
            return Ok(Some(status));
        }
        if r < 0 {
            let e = last_errno();
            if e == Errno::INTR {
                continue;
            }
            // `ECHILD` — already reaped; upstream's `waitpid` loops
            // treat it as done.
            if e == Errno::CHILD {
                return Ok(Some(0));
            }
            return Err(e);
        }
        return Ok(None);
    }
}

/// `waitpid(-1, &mut status, WNOHANG)` — the monitor's stray-descendant
/// drain. `Some` = a child was reaped; `None` = nothing was reapable
/// (`ECHILD` included — upstream returns done for both).
pub fn wait_any_nohang() -> Result<Option<i32>, Errno> {
    let mut status: libc::c_int = 0;
    // SAFETY: `status` is a live int; -1 waits for any child.
    let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    if r > 0 {
        return Ok(Some(r));
    }
    if r < 0 {
        let e = last_errno();
        if e == Errno::CHILD {
            return Ok(None);
        }
        return Err(e);
    }
    Ok(None)
}

/// `kill(pid, sig)` for a raw pid — upstream's `kill(worker_pid, …)`
/// and `kill(monitor_pid, SIGKILL)` fallback.
pub fn kill_pid(pid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    if unsafe { libc::kill(pid, sig) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `kill(-pgid, sig)` — the worker's whole process group (upstream's
/// `kill(-worker_pid, SIGKILL)`; the worker is `setsid`'d so its pid
/// is its group).
pub fn kill_pgroup(pgid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    if unsafe { libc::kill(-pgid, sig) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `kill(-pgid, 0)` ESRCH probe — upstream's
/// `kill(-worker_pid, 0) == 0 || errno != ESRCH → fail`: the group is
/// gone only when the probe is ESRCH (0 or EPERM still means members).
pub fn pgroup_gone(pgid: i32) -> bool {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    if unsafe { libc::kill(-pgid, 0) } == 0 {
        return false;
    }
    last_errno() == Errno::SRCH
}

/// `pidfd_open(pid, 0)` — upstream's `open_pidfd`. The fd-cloexec is
/// applied by the caller (upstream `fcntl(fd, F_SETFD, FD_CLOEXEC)`).
pub fn pidfd_open(pid: i32) -> Result<OwnedFd, Errno> {
    let Some(p) = rustix::process::Pid::from_raw(pid) else {
        return Err(Errno::INVAL);
    };
    central_adapter_linux::sys::pidfd::open(p).map_err(|_| Errno::INVAL)
}

/// `pidfd_send_signal(fd, sig, NULL, 0)` — the record's SIGKILL of its
/// monitor when the completion channel cannot prove the tree is gone.
/// The primitive lives in the shared audited site; this shim bridges
/// the raw fd the record holds into its owned signature.
pub fn pidfd_send_signal(pidfd: RawFd, sig: i32) -> Result<(), Errno> {
    use rustix::process::Signal;
    // SAFETY: `pidfd` is an open pidfd the record owns for the call's
    // duration; `borrow_raw` creates no ownership.
    let fd = unsafe { BorrowedFd::borrow_raw(pidfd) };
    let signal = Signal::from_named_raw(sig).ok_or(Errno::INVAL)?;
    central_adapter_linux::sys::pidfd::send_signal(fd, signal).map_err(|_| Errno::INVAL)
}

/// Borrow a fixed, always-open descriptor (the monitor's 0-7 and the
/// worker's 0-6) so the safe rustix APIs can take it.
pub fn borrow(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: the call sites use this only for descriptors the process
    // keeps open for the scope of the call (the monitor's fixed 3-7
    // channels, a record's live fds).
    unsafe { BorrowedFd::borrow_raw(fd) }
}

/// Install `handler` as `sig`'s action with an empty mask.
///
/// # Safety contract
/// `handler` must be an `extern "C"` function (or `SIG_IGN`). The
/// handlers installed by this daemon only set an atomic flag — safe
/// from a signal context.
pub fn sigaction_handler(sig: libc::c_int, handler: usize) {
    // SAFETY: all-zero is a valid `libc::sigaction` representation.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler;
    // SAFETY: empty mask is a plain field write.
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    // SAFETY: `sa` is a fully initialised sigaction for `sig`.
    unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) };
}

/// `SIG_IGN` as a `sigaction` handler value.
pub const SIG_IGN: usize = 1;

/// `path` (NUL-free bytes) as an owned `CString`.
pub fn bytes_cstring(b: &[u8]) -> Option<CString> {
    CString::new(b).ok()
}
