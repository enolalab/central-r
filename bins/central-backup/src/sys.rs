//! Audited raw-descriptor half of the `central-backup` launcher grammar.
//!
//! Every `unsafe` of this binary lives behind a named safe wrapper here
//! so `main.rs` stays free of `unsafe` entirely — the same shape
//! `central-backup-launcherd`'s `sys.rs` uses. FD 3 (launch evidence
//! bytes) is consumed and closed; FD 4 (repository root) is made
//! `FD_CLOEXEC` and shape-checked; FD 5 (CBW1 monitor channel) is
//! adopted by the kernel composition's `TargetLockHandoff::prepare`.
//!
//! `libc` carries the `F_GETFD`/`F_SETFD` sites rustix has no wrapper
//! for in the pinned version — identical to the adapter's audited
//! boundary.
#![allow(unsafe_code)]

use std::io::Read;
use std::os::fd::{BorrowedFd, FromRawFd, RawFd};

use rustix::fs::{FileType, fstat};

/// `borrow_process_fd` — a live inherited descriptor borrowed for the
/// rest of the process. The number stays owned by the supervisor's
/// inherited slot; nothing closes it through the borrow.
pub fn borrow_process_fd(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: `fd` names an inherited descriptor the supervisor opened
    // before exec; callers use it read-only and never close through
    // the borrow.
    unsafe { BorrowedFd::borrow_raw(fd) }
}

/// `consumeLaunchEvidence`'s descriptor half — `os.NewFile(fd)` plus
/// `defer file.Close()`: adopt the slot, read exactly `out.len()`
/// bytes, then require immediate EOF so a padded channel refuses.
///
/// # Errors
/// Any read failure, a short read, or trailing bytes.
pub fn read_exact_to_eof_and_close(fd: RawFd, out: &mut [u8]) -> std::io::Result<()> {
    // SAFETY: the caller passes the fixed inherited evidence
    // descriptor it is authorized to consume; adopting it mirrors
    // upstream's `file.Close()` once the bytes are read.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.read_exact(out)?;
    let mut extra = [0u8; 1];
    match file.read(&mut extra) {
        Ok(0) => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trailing bytes",
        )),
        Err(e) => Err(e),
    }
}

/// `unix.FcntlInt(fd, F_GETFD)` + `F_SETFD(FD_CLOEXEC)` — the
/// repository descriptor can never leak into `pg_dump`.
pub fn mark_cloexec(fd: RawFd) -> Result<(), rustix::io::Errno> {
    // SAFETY: `fd` is a number, not a pointer — `fcntl` cannot touch
    // memory; on a closed descriptor it fails with `EBADF` and
    // performs no state change.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(last_errno());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `errno` after a failed `fcntl` — `Errno` from the thread-local
/// `std::io` copy, `INVAL` if unset.
fn last_errno() -> rustix::io::Errno {
    rustix::io::Errno::from_io_error(&std::io::Error::last_os_error())
        .unwrap_or(rustix::io::Errno::INVAL)
}

/// `fcntl(fd, F_GETFD) & FD_CLOEXEC` — the descriptor's own
/// close-on-exec bit. Only the grammar tests observe it; the
/// production path proves CLOEXEC by setting it.
#[cfg(test)]
pub fn is_cloexec(fd: RawFd) -> bool {
    // SAFETY: `fd` is a number, not a pointer — `fcntl` cannot touch
    // memory; on a closed descriptor it fails and `false` reports.
    unsafe { libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
}

/// `fcntl(fd, F_GETFD) != -1` — the slot is still open. Grammar tests
/// only; descriptor-number reuse makes any by-number check racy, so
/// tests pair it with the serial fd guard.
#[cfg(test)]
pub fn is_open(fd: RawFd) -> bool {
    // SAFETY: as `is_cloexec`.
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

/// `unix.Fstat` + `S_IFMT == S_IFDIR` — the repository descriptor
/// must name a directory.
pub fn is_directory(fd: RawFd) -> bool {
    fstat(borrow_process_fd(fd))
        .map(|s| FileType::from_raw_mode(s.st_mode).is_dir())
        .unwrap_or(false)
}
