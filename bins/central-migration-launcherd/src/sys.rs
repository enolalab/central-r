//! Audited syscall boundary (workflow §5.2).
//!
//! Every `unsafe` of this binary lives behind a named safe wrapper
//! here — the sites rustix 1.1 has no safe API for: `fork`/`execve`,
//! `dup2`/`dup3` to fixed descriptor numbers, `close_range`,
//! `setgroups`/`setuid`/`setgid`, `sigaction` handler install,
//! `_exit`, `waitpid` on a raw child pid, `fcntl` `F_SETFD` clearing
//! `FD_CLOEXEC` on the fixed launch descriptors, `pidfd_open`'s raw
//! variant returning an owned fd, and the systemd `F_DUPFD_CLOEXEC`
//! activation dup. The raw-fd ownership bridges ([`borrow`],
//! [`owned`]) are here too so the rest of the crate stays free of
//! `unsafe` entirely. `SO_PEERCRED`, `SCM_RIGHTS`, `pidfd_send_signal`
//! and `kill` themselves live in the shared audited site —
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
/// [`exit`] or [`execve`] — the caller guarantees it (the launch path
/// never returns to Rust-managed state).
pub fn fork() -> Result<Fork, Errno> {
    // SAFETY: plain fork; the child path is documented above.
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
    // in main.rs right before this call.
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
/// (FD3/FD4) and `O_CLOEXEC` for the diagnostics fd that must not.
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

/// `fcntl(fd, F_SETFD, flags)` — clears `FD_CLOEXEC` on a descriptor
/// that must survive `execve` (the fixed FD3/FD4 handoff).
pub fn clear_cloexec(fd: RawFd) -> Result<(), Errno> {
    // SAFETY: fcntl on an open descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `close(2)` on a raw fd — a no-op on an already-closed number.
pub fn close(fd: RawFd) {
    // SAFETY: closing a descriptor number is harmless.
    unsafe { libc::close(fd) };
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
/// like upstream's `#ifndef CENTRAL_LAUNCHER_TEST_PEER_UID` — a
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
            // `ECHILD` — already reaped; upstream's `waitpid` loop
            // treats it as done (a `kill_record` on a reaped record is
            // a no-op).
            if e == Errno::CHILD {
                return Ok(Some(0));
            }
            return Err(e);
        }
        return Ok(None);
    }
}

/// `pidfd_open(pid, 0)` + `FD_CLOEXEC`, upstream's helper — the record
/// keeps the descriptor across the loop.
pub fn pidfd_open(pid: i32) -> Result<OwnedFd, Errno> {
    let Some(p) = rustix::process::Pid::from_raw(pid) else {
        return Err(Errno::INVAL);
    };
    central_adapter_linux::sys::pidfd::open(p).map_err(|_| Errno::INVAL)
}

/// `kill(pid, sig)` for a raw pid — the fallback when a record lost
/// its pidfd, upstream's `kill_record` second arm.
pub fn kill_pid(pid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    if unsafe { libc::kill(pid, sig) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `pidfd_send_signal(fd, sig, NULL, 0)` — the record's SIGKILL of its
/// uncommitted or shutdown launch. The primitive itself lives in the
/// shared audited site; this shim bridges the raw fd the record holds
/// into its owned signature.
pub fn pidfd_send_signal(pidfd: RawFd, sig: i32) -> Result<(), Errno> {
    use rustix::process::Signal;
    // SAFETY: `pidfd` is an open pidfd the record owns for the call's
    // duration; `borrow_raw` creates no ownership.
    let fd = unsafe { BorrowedFd::borrow_raw(pidfd) };
    let signal = Signal::from_named_raw(sig).ok_or(Errno::INVAL)?;
    central_adapter_linux::sys::pidfd::send_signal(fd, signal).map_err(|_| Errno::INVAL)
}

/// `fcntl(3, F_DUPFD_CLOEXEC, 5)` — the systemd socket-activation
/// claim, upstream `listener_from_systemd`.
pub fn dupfd_cloexec(fd: RawFd, min: RawFd) -> Result<OwnedFd, Errno> {
    // SAFETY: fcntl on an open descriptor; the result is owned.
    let r = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
    if r < 0 {
        return Err(last_errno());
    }
    // SAFETY: `r` is a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// Install `handler` as `sig`'s action with an empty mask.
///
/// # Safety contract
/// `handler` must be an `extern "C"` function (or `SIG_IGN`). The
/// handlers installed by this daemon only set an atomic flag — safe
/// from a signal context.
pub fn sigaction_handler(sig: libc::c_int, handler: usize) {
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
