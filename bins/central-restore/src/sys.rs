//! Audited raw-descriptor half of the `central-restore` engine
//! grammar.
//!
//! Every `unsafe` of this binary lives behind a named safe wrapper
//! here so `main.rs` stays free of `unsafe` entirely — the same shape
//! `central-backup`'s `sys.rs` uses. The fixed slots the root helper
//! pins are: FD 3 (protected broker root), FD 4 (read-only repository
//! root), FDs 5–8 (the four capacity role roots), FD 9 (launch-gate
//! read end — adopted and closed by the gate wait), and FD 10
//! (import staging, present only for `import` launches).
#![allow(unsafe_code)]

use std::os::fd::{BorrowedFd, FromRawFd, RawFd};

/// `borrow_process_fd` — a live inherited descriptor borrowed for the
/// rest of the process. The number stays owned by the launcher's
/// inherited slot; nothing closes it through the borrow.
pub fn borrow_process_fd(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: `fd` names an inherited descriptor the root helper
    // opened before exec; callers use it read-only and never close
    // through the borrow.
    unsafe { BorrowedFd::borrow_raw(fd) }
}

/// `os.NewFile(restoreLaunchGateFD)` + `defer gate.Close()` — adopt
/// the launch-gate read end so the gate wait owns exactly one close.
/// The returned [`std::fs::File`] closes the descriptor on drop,
/// matching upstream's deferred `gate.Close()`.
///
/// # Errors
/// `EBADF` surfaces later as a read error on the returned file —
/// identical to upstream, where `os.NewFile` on a dead slot produces
/// a file whose first read fails and the gate wait fails closed.
pub fn adopt_launch_gate(fd: RawFd) -> std::fs::File {
    // SAFETY: `fd` is the fixed inherited gate slot the launcher
    // pinned for exactly this adoption; this is the only site that
    // takes ownership of it.
    unsafe { std::fs::File::from_raw_fd(fd) }
}
