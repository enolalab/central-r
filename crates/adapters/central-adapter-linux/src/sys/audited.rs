//! Audited syscall boundary (workflow §5.2; R5 decision D2).
//!
//! Every `unsafe` block of `central-adapter-linux` lives behind a named
//! safe wrapper here — the sites rustix 1.1 has no safe API for:
//!
//! - [`install_filter`] — `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC, prog)`
//!   (upstream `hardening.go`'s `unix.Syscall(unix.SYS_SECCOMP, …)`;
//!   rustix's `thread::set_secure_computing_mode` covers only the strict
//!   mode, not a `sock_fprog` install, so the call goes through `libc`
//!   exactly as D2 decided).
//! - [`unshare`] — `unshare(flags)`: rustix marks
//!   [`rustix::thread::unshare_unsafe`] `unsafe` because the
//!   `CLONE_FILES`/`CLONE_FS` flags can detach the caller's descriptor
//!   table; [`sys::namespace`] admits only `CLONE_NEW*` namespace flags,
//!   so that hazard is statically excluded at the call site.
//!
//! [`sys::namespace`]: crate::sys::namespace

#![allow(unsafe_code)]

use rustix::io::Errno;

/// The current `errno` value after a libc call reported `-1`.
pub(crate) fn last_errno() -> Errno {
    Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::INVAL)
}

/// `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, prog)` —
/// install `prog` on every thread of the calling process
/// (`sys::seccomp::install`). `TSYNC` is upstream's flag and the only
/// honest install for a daemon: a filter that covers only the calling
/// thread would leave the broker's other threads unfiltered.
///
/// `prog` must point at a live `sock_filter` array — the caller
/// (`sys::seccomp`) builds it from a `Vec<libc::sock_filter>` that
/// outlives the call; the kernel copies the program before returning,
/// so no reference is retained.
pub(crate) fn install_filter(prog: &libc::sock_fprog) -> Result<(), Errno> {
    // SAFETY: `prog` is a reference to a live `sock_fprog` whose
    // `filter` pointer names a `sock_filter` array of `len` entries —
    // `sys::seccomp::install` builds it from a slice and the kernel
    // copies the program synchronously, so the pointer cannot dangle
    // and no aliased mutation races the read. `SYS_seccomp` with
    // SET_MODE_FILTER|TSYNC installs the filter on all threads of this
    // process; it does not touch user memory beyond `prog` itself.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            prog,
        )
    };
    if r != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `unshare(flags)` — rustix's safe `unshare` is deprecated in favour of
/// `unshare_unsafe`, which is `unsafe` only because `CLONE_FILES` /
/// `CLONE_FS` would detach the caller's descriptor table. The wrapper
/// takes [`sys::namespace::NamespaceFlags`], whose bits can only ever
/// hold `CLONE_NEW*` namespace flags, so that hazard is statically
/// excluded at the type level.
///
/// [`sys::namespace::NamespaceFlags`]: crate::sys::namespace::NamespaceFlags
pub(crate) fn unshare(flags: crate::sys::namespace::NamespaceFlags) -> Result<(), Errno> {
    let flags = flags.bits();
    debug_assert_eq!(
        flags & !crate::sys::namespace::NamespaceFlags::ALL.bits(),
        rustix::thread::UnshareFlags::empty(),
        "NamespaceFlags carries only CLONE_NEW* bits by construction"
    );
    // SAFETY: `flags` contains only `CLONE_NEW*` namespace bits —
    // `NamespaceFlags`'s private constructor admits nothing else — so
    // `FILES`/`FS`, the two flags whose fd-table detach is why rustix
    // marks this call unsafe, can never be set here.
    unsafe { rustix::thread::unshare_unsafe(flags) }
}
