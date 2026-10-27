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
//! - [`pam_ffi`] — the hand-written Linux-PAM FFI (R5 task 5, decision
//!   D1): `pam_start` → `pam_authenticate` → `pam_end` and the
//!   conversation callback, byte-exact the upstream cgo shim
//!   (`internal/adapter/authority/helper/pam_linux.go`). `sys::pam`
//!   is the safe front door.
//!
//! [`sys::namespace`]: crate::sys::namespace
//! [`pam_ffi`]: self::pam_ffi

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

/// `sigaction(signum, {handler, empty mask, SA_RESTART})` — installs a
/// plain-C handler with no flags beyond `SA_RESTART`, glibc's
/// `sigaction(3)` entry point so the restorer is wired exactly as a C
/// program's. The handler must be async-signal-safe; the only caller
/// (`broker::daemon`'s shutdown flag) stores one word to a `static`
/// `AtomicBool` — the `signal.NotifyContext(SIGINT, SIGTERM)` shape
/// without tokio's signal driver, whose self-pipe `socketpair` (53) is
/// not on the broker's seccomp allow-list (ADR 0044).
///
/// `rt_sigaction` (13) IS allow-listed, so this survives `harden()` —
/// which is the point: the daemon arms the flag before `install()` and
/// the handler must keep working under the filter.
///
/// # Errors
/// `Errno` of the `sigaction` failure (`EINVAL` for an unusable
/// signum — `SIGKILL`/`SIGSTOP` cannot be caught).
pub(crate) fn install_signal_handler(
    signum: libc::c_int,
    handler: extern "C" fn(libc::c_int),
) -> Result<(), Errno> {
    // SAFETY: `act` names a live `sigaction` for the call's duration.
    // `handler` is an `extern "C"` fn item — a valid handler address by
    // type — and `SA_RESTART` + an empty mask matches upstream
    // `signal.NotifyContext`'s disposition. libc::sigaction installs
    // the kernel's required SA_RESTORER trampoline itself.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = handler as usize;
        act.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&raw mut act.sa_mask);
        if libc::sigaction(signum, &raw const act, std::ptr::null_mut()) != 0 {
            return Err(last_errno());
        }
    }
    Ok(())
}

/// `fstatfs(fd, &statfs)` returning only `f_fsid` — the filesystem
/// identity rustix's `StatFs` struct keeps private. The recovery
/// capacity boundary (upstream `capacity_linux.go`'s
/// `opaqueFilesystemID`) hashes exactly this kernel value into its
/// opaque device identity, so substituting `st_dev` would change the
/// evidence bytes the binding pins.
///
/// # Errors
/// `Errno` of the `fstatfs` failure.
pub(crate) fn statfs_fsid<Fd: std::os::fd::AsFd>(fd: Fd) -> Result<u64, Errno> {
    // SAFETY: `stat` is a live zeroed `statfs` out-buffer for the
    // call's duration; `fd` borrows a live descriptor for the syscall
    // only. `f_fsid` is `fsid_t` — a two-`int` struct (`__fsid_t`) —
    // and this reads exactly those public `val` fields.
    unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        if libc::fstatfs(std::os::fd::AsRawFd::as_raw_fd(&fd.as_fd()), &raw mut stat) != 0 {
            return Err(last_errno());
        }
        // SAFETY: `fsid_t` is `__fsid_t`, a `repr(C)` struct of
        // exactly two `c_int`s (its only member, private in libc's
        // bindings); transmuting the 8-byte copyable value to
        // `[c_int; 2]` reads the same `val[0]`/`val[1]` upstream's
        // `unix.Statfs_t.Fsid.Val` exposes — same size, same
        // alignment, same two fields, nothing else.
        let val: [libc::c_int; 2] = std::mem::transmute(stat.f_fsid);
        Ok((u64::from(val[0] as u32) << 32) | u64::from(val[1] as u32))
    }
}

/// `nanosleep(2)` — the raw syscall, not the library shape.
/// `std::thread::sleep` and glibc's `nanosleep` both route through
/// `clock_nanosleep` (230) on this toolchain; the broker's seccomp
/// allow-list carries `nanosleep` (35) only (ADR 0044). Used by the
/// accept poll and the connection-deadline cadence.
///
/// `EINTR` returns early — callers that need the full duration loop
/// on their own deadline; both existing callers do.
pub(crate) fn nanosleep(dur: std::time::Duration) {
    let ts = libc::timespec {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_nsec: i64::from(dur.subsec_nanos()) as libc::c_long,
    };
    // SAFETY: `ts` is a live `timespec` for the call's duration; the
    // remainder out-param is NULL — the interrupt is the caller's to
    // handle.
    unsafe {
        libc::syscall(
            libc::SYS_nanosleep,
            &raw const ts,
            std::ptr::null_mut::<libc::timespec>(),
        );
    }
}

/// `LISTEN_FDS` socket activation: fd `3 + index` is handed to this
/// process by the supervisor — the descriptor is owned exclusively by
/// this process per the activation contract, so wrapping it in
/// `OwnedFd` transfers ownership without aliasing. The caller validates
/// `LISTEN_PID`/`LISTEN_FDS` before reaching here.
///
/// # Errors
/// `EBADF` when the fd is not open.
/// Raw `statx` — the test-only emission the `old-statx` probe pins to
/// `SIGSYS` (R5 T9 / ADR 0044). `std::fs::metadata` reaches this
/// syscall on modern toolchains; the fixed port uses `statat` /
/// `newfstatat` (262), which the filter lists. Not for production
/// callers: this exists only so the probe can fire the denied syscall
/// deterministically under `#[forbid(unsafe_code)]` seccomp tests.
///
/// # Errors
/// Returns the raw syscall result (`-errno` style `c_long`) — under
/// the installed filter it never returns at all.
#[cfg(test)]
pub(crate) fn statx_raw(path: &core::ffi::CStr) -> libc::c_long {
    // SAFETY: `stx` is a live zeroed `statx` out-buffer for the call's
    // duration and `path` is a live C string; a denied statx is killed
    // by the filter before any return value matters.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    unsafe {
        libc::syscall(
            libc::SYS_statx,
            libc::AT_FDCWD,
            path.as_ptr(),
            0,
            libc::STATX_ALL,
            &raw mut stx,
        )
    }
}

/// Raw `rename` (82) — the syscall `std::fs::rename` emits
/// unconditionally on x86_64; the `old-rename` probe pins it to
/// `SIGSYS` (R5 T9 P0-A round 2 / ADR 0044). Not for production
/// callers: the allow-listed shape is `renameat`/`renameat2` via
/// `broker::durable::rename_replace`/`rename_noreplace`.
///
/// # Errors
/// Returns the raw syscall result (`-errno` style `c_long`) — under
/// the installed filter it never returns at all.
#[cfg(test)]
pub(crate) fn rename_raw(old: &core::ffi::CStr, new: &core::ffi::CStr) -> libc::c_long {
    // SAFETY: both C strings are live for the call's duration; a
    // denied rename is killed by the filter on entry, before any
    // return value matters.
    unsafe { libc::syscall(libc::SYS_rename, old.as_ptr(), new.as_ptr()) }
}

/// Raw `unlink` (87) — the syscall `std::fs::remove_file` emits on
/// glibc ≥ 2.37 (`unlinkat` on older); the `old-unlink` probe pins it
/// to `SIGSYS` (R5 T9 P0-A round 2 / ADR 0044). Not for production
/// callers: the allow-listed shape is `unlinkat` via
/// `broker::durable::remove_file`/`remove_all`.
///
/// # Errors
/// Returns the raw syscall result — under the installed filter it
/// never returns at all.
#[cfg(test)]
pub(crate) fn unlink_raw(path: &core::ffi::CStr) -> libc::c_long {
    // SAFETY: `path` is a live C string for the call's duration.
    unsafe { libc::syscall(libc::SYS_unlink, path.as_ptr()) }
}

/// Raw `link` (86) — the syscall `std::fs::hard_link` emits on glibc ≥
/// 2.37; the `old-link` probe pins it to `SIGSYS` (R5 T9 P0-A round 2 /
/// ADR 0044). Not for production callers: the allow-listed shape is
/// `linkat` via `broker::durable::hard_link`.
///
/// # Errors
/// Returns the raw syscall result — under the installed filter it
/// never returns at all.
#[cfg(test)]
pub(crate) fn link_raw(old: &core::ffi::CStr, new: &core::ffi::CStr) -> libc::c_long {
    // SAFETY: both C strings are live for the call's duration.
    unsafe { libc::syscall(libc::SYS_link, old.as_ptr(), new.as_ptr()) }
}

/// Raw `fchownat` (260) — the syscall `rustix::fs::chown` (and `std`'s
/// `chown`-family paths) emit on Linux; the `old-fchownat` probe pins
/// it to `SIGSYS` (R5 T9 P0-A round 2 / ADR 0044). Not for production
/// callers: the allow-listed shape is `fchown` (93) on an open fd.
///
/// # Errors
/// Returns the raw syscall result — under the installed filter it
/// never returns at all.
#[cfg(test)]
pub(crate) fn fchownat_raw(path: &core::ffi::CStr) -> libc::c_long {
    // SAFETY: `path` is a live C string for the call's duration; the
    // uid/gid are irrelevant — the filter kills the call on entry.
    unsafe { libc::syscall(libc::SYS_fchownat, libc::AT_FDCWD, path.as_ptr(), 0, 0, 0) }
}

/// `getpwnam(3)` — name → `(uid, gid, name, home)`. rustix has no NSS
/// API; the record is copied out of the thread-static return buffer
/// before it can be invalidated. Callers must be single-threaded with
/// respect to NSS (the daemon and helper are).
pub(crate) fn getpwnam(
    name: &core::ffi::CStr,
) -> Option<(u32, u32, std::ffi::CString, std::ffi::CString)> {
    // SAFETY: `name` is a valid NUL-terminated string; the returned
    // thread-static `passwd` is read completely before returning.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: `pw` is a live `passwd` record (checked non-null above).
    unsafe {
        Some((
            (*pw).pw_uid,
            (*pw).pw_gid,
            core::ffi::CStr::from_ptr((*pw).pw_name).to_owned(),
            core::ffi::CStr::from_ptr((*pw).pw_dir).to_owned(),
        ))
    }
}

/// `getgrnam(3)` — group name → gid. Same thread-static read pattern
/// as [`getpwnam`].
pub(crate) fn getgrnam(name: &core::ffi::CStr) -> Option<u32> {
    // SAFETY: `name` is a valid NUL-terminated string; `gr` is checked
    // non-null before the single field read.
    let gr = unsafe { libc::getgrnam(name.as_ptr()) };
    if gr.is_null() {
        None
    } else {
        // SAFETY: `gr` is a live `group` record (checked non-null).
        Some(unsafe { (*gr).gr_gid })
    }
}

/// `pidfd_send_signal(pidfd, sig, NULL, 0)` — signal the process a
/// pidfd names (carried forward from `central-harness-launcherd`'s
/// monitor SIGTERM/SIGKILL of its namespace init, R5 task 14 D5).
/// rustix 1.1 has no `pidfd_send_signal` wrapper.
pub(crate) fn pidfd_send_signal(fd: std::os::fd::RawFd, sig: i32) -> Result<(), Errno> {
    // SAFETY: `pidfd_send_signal` takes a descriptor number and a
    // signal value; no memory is shared. The caller proves the fd is a
    // live pidfd (`sys::pidfd` call sites borrow only owned handles).
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            sig,
            std::ptr::null::<u8>(),
            0,
        )
    } != 0
    {
        return Err(last_errno());
    }
    Ok(())
}

pub(crate) fn socket_activation_fd(index: u32) -> Result<std::os::fd::OwnedFd, Errno> {
    let raw = 3i32 + i32::try_from(index).map_err(|_| Errno::BADF)?;
    // SAFETY: the socket-activation contract makes `3 + index` an open
    // descriptor owned solely by this process; `OwnedFd::from_raw_fd`
    // takes that ownership. `fcntl(F_GETFD)` proves it is open before
    // we claim it so a bad index cannot alias an unrelated fd number.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(last_errno());
    }
    // SAFETY: `raw` was just proven open by `F_GETFD` and is owned by
    // this process under the activation contract.
    use std::os::fd::FromRawFd as _;
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

/// Hand-written Linux-PAM FFI (`pam`), R5 task 5 / decision D1.
///
/// This is a byte-exact port of the upstream cgo shim
/// `central_pam_authenticate` in
/// `internal/adapter/authority/helper/pam_linux.go`:
///
/// ```c
/// struct pam_conv conversation = { central_pam_conversation, &data };
/// int result = pam_start(service, username, &conversation, &pamh);
/// if (result == PAM_SUCCESS) result = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
/// if (pamh != NULL) pam_end(pamh, result);
/// ```
///
/// Upstream does **not** call `pam_acct_mgmt` — authentication is the
/// whole observable contract, so the declared surface is exactly the
/// three calls upstream makes plus the conversation callback. The
/// constants and `repr(C)` layouts below are the Linux-PAM ABI from
/// `<security/_pam_types.h>` and `<security/pam_appl.h>`.
pub(crate) mod pam_ffi {
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::ptr;

    /// `PAM_SUCCESS` — `<security/_pam_types.h>`.
    pub(crate) const PAM_SUCCESS: c_int = 0;
    /// `PAM_BUF_ERR` — `<security/_pam_types.h>`.
    const PAM_BUF_ERR: c_int = 5;
    /// `PAM_CONV_ERR` — `<security/_pam_types.h>`.
    const PAM_CONV_ERR: c_int = 19;
    /// `PAM_PROMPT_ECHO_OFF` — `<security/_pam_types.h>`; the only
    /// prompt style the conversation will ever answer with data.
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    /// `PAM_PROMPT_ECHO_ON` — `<security/_pam_types.h>`; declared so
    /// the tests can name the style the conversation must refuse.
    /// Never matched in the callback — echo-on falls into the
    /// fail-closed arm like every unknown style.
    #[allow(dead_code)]
    const PAM_PROMPT_ECHO_ON: c_int = 2;
    /// `PAM_ERROR_MSG` — `<security/_pam_types.h>`; tolerated (no
    /// data), as upstream tolerates it.
    const PAM_ERROR_MSG: c_int = 3;
    /// `PAM_TEXT_INFO` — `<security/_pam_types.h>`; tolerated (no
    /// data), as upstream tolerates it.
    const PAM_TEXT_INFO: c_int = 4;
    /// `PAM_DISALLOW_NULL_AUTHTOK` — `<security/_pam_types.h>`;
    /// upstream's `pam_authenticate` flag.
    const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x0001;

    /// `struct pam_message` — `<security/_pam_types.h>`:
    /// `{ int msg_style; const char *msg; }`.
    #[repr(C)]
    pub(crate) struct PamMessage {
        msg_style: c_int,
        #[allow(dead_code)]
        msg: *const c_char,
    }

    /// `struct pam_response` — `<security/_pam_types.h>`:
    /// `{ char *resp; int resp_retcode; }`.
    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        #[allow(dead_code)]
        resp_retcode: c_int,
    }

    /// `struct pam_conv` — `<security/_pam_types.h>`:
    /// `{ int (*conv)(...); void *appdata_ptr; }`.
    #[repr(C)]
    struct PamConv {
        conv: Option<
            unsafe extern "C" fn(
                c_int,
                *const *const PamMessage,
                *mut *mut PamResponse,
                *mut c_void,
            ) -> c_int,
        >,
        appdata_ptr: *mut c_void,
    }

    /// `pam_handle_t` — opaque to callers (`<security/pam_appl.h>`
    /// only ever hands out `pam_handle_t*`).
    #[repr(C)]
    struct PamHandle {
        _private: [u8; 0],
    }

    // SAFETY: these declarations match `<security/pam_appl.h>` on
    // Linux-PAM byte-for-byte — argument types, return type, and the
    // out-pointer contract of `pam_start` — verified against the
    // reference host's headers for R5 task 5.
    unsafe extern "C" {
        /// `int pam_start(const char *service_name, const char *user,
        /// const struct pam_conv *pam_conversation, pam_handle_t **pamh);`
        fn pam_start(
            service_name: *const c_char,
            user: *const c_char,
            pam_conversation: *const PamConv,
            pamh: *mut *mut PamHandle,
        ) -> c_int;
        /// `int pam_authenticate(pam_handle_t *pamh, int flags);`
        fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
        /// `int pam_end(pam_handle_t *pamh, int pam_status);`
        fn pam_end(pamh: *mut PamHandle, pam_status: c_int) -> c_int;
    }

    /// `free_responses` — release a response array the conversation
    /// partially filled, freeing each `strdup`ed entry first. Upstream
    /// frees only the array and leaks the earlier copies; freeing the
    /// entries too is strictly tighter on a path that can only run on
    /// failure.
    ///
    /// `filled` is how many leading entries may hold a `strdup`ed
    /// pointer (entries are `calloc`ed, so the rest are NULL).
    ///
    /// # Safety
    /// `replies` must be a `libc::calloc` allocation of at least
    /// `filled` `PamResponse`s, or NULL.
    unsafe fn free_responses(replies: *mut PamResponse, filled: c_int) {
        if replies.is_null() {
            return;
        }
        for i in 0..filled {
            // SAFETY: `replies` is a live calloc allocation of at
            // least `filled` entries (the caller guarantees the
            // bound); `resp` entries are either NULL (calloc) or a
            // `libc::strdup` allocation, both safe to pass to
            // `libc::free`.
            let entry = unsafe { (*replies.add(i as usize)).resp };
            if !entry.is_null() {
                // SAFETY: `entry` is a live `strdup` allocation as
                // established above.
                unsafe { libc::free(entry.cast()) };
            }
        }
        // SAFETY: `replies` is the `calloc` allocation established
        // above.
        unsafe { libc::free(replies.cast()) };
    }

    /// `central_pam_conversation` — the conversation callback,
    /// byte-exact the upstream C:
    ///
    /// - `PAM_PROMPT_ECHO_OFF` → `strdup(password)` (the only style
    ///   ever answered with data);
    /// - `PAM_TEXT_INFO`, `PAM_ERROR_MSG` → tolerated, response entry
    ///   stays NULL — upstream explicitly admits both and so must we:
    ///   a real `common-auth` stack may surface informational lines,
    ///   and refusing them would deny legitimate authentications that
    ///   upstream accepts;
    /// - anything else (`PAM_PROMPT_ECHO_ON`, unknown `msg_style`) →
    ///   `PAM_CONV_ERR` — fail closed, no data ever leaves.
    ///
    /// # Safety
    /// Called only by libpam, on the thread inside `pam_authenticate`,
    /// with `appdata_ptr` being the `*const c_char` secret pointer
    /// [`authenticate`] installed in `PamConv` — a live NUL-terminated
    /// string that outlives the whole call.
    unsafe extern "C" fn conversation(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut c_void,
    ) -> c_int {
        if num_msg < 0 || msg.is_null() || resp.is_null() || appdata_ptr.is_null() {
            return PAM_CONV_ERR;
        }
        let password = appdata_ptr.cast::<c_char>();
        // SAFETY: `calloc` returns a zeroed allocation of
        // `num_msg * size_of::<PamResponse>()` bytes or NULL; the NULL
        // case is checked. The allocation is handed to libpam below
        // (it frees `pam_response` arrays after the conversation) or
        // freed by `free_responses` on the error paths.
        let replies = unsafe { libc::calloc(num_msg as usize, size_of::<PamResponse>()) }
            .cast::<PamResponse>();
        if replies.is_null() {
            return PAM_CONV_ERR;
        }
        for i in 0..num_msg {
            // SAFETY: the libpam conversation contract passes `msg` as
            // a pointer to an array of `num_msg` pointers, each naming
            // a live `pam_message` for the duration of the call.
            let message = unsafe { *msg.add(i as usize) };
            if message.is_null() {
                // SAFETY: `replies` is our calloc allocation of
                // `num_msg` entries; `i` bounds the filled prefix.
                unsafe { free_responses(replies, i) };
                return PAM_CONV_ERR;
            }
            // SAFETY: `message` is a live `pam_message` per the
            // contract above.
            let style = unsafe { (*message).msg_style };
            if style == PAM_PROMPT_ECHO_OFF {
                // SAFETY: `password` is the NUL-terminated secret
                // `authenticate` installed; it outlives this call.
                // `strdup` allocates a copy libpam frees after use.
                let copy = unsafe { libc::strdup(password) };
                if copy.is_null() {
                    // SAFETY: as above — `i` bounds the filled prefix.
                    unsafe { free_responses(replies, i) };
                    return PAM_BUF_ERR;
                }
                // SAFETY: `replies` has `num_msg` entries and `i` is
                // in bounds.
                unsafe { (*replies.add(i as usize)).resp = copy };
            } else if style != PAM_TEXT_INFO && style != PAM_ERROR_MSG {
                // SAFETY: as above — `i` bounds the filled prefix.
                unsafe { free_responses(replies, i) };
                return PAM_CONV_ERR;
            }
        }
        // SAFETY: `resp` is the out-pointer libpam handed us, checked
        // non-NULL above; `replies` ownership passes to libpam here.
        unsafe { *resp = replies };
        PAM_SUCCESS
    }

    /// `central_pam_authenticate(service, userName, secret)` — the
    /// upstream C shim verbatim: `pam_start`, then
    /// `pam_authenticate(PAM_DISALLOW_NULL_AUTHTOK)` on success, then
    /// `pam_end` propagating the result as the final status. The raw
    /// PAM result code is returned for `sys::pam` to map onto the
    /// closed denial envelope — this function never maps anything to
    /// success except `PAM_SUCCESS` itself.
    pub(crate) fn authenticate(service: &CStr, user: &CStr, secret: &CStr) -> c_int {
        let conversation = PamConv {
            conv: Some(conversation),
            // The upstream shim passes `&data` where data wraps the
            // password pointer; passing the pointer itself is the same
            // contract with our own callback.
            appdata_ptr: secret.as_ptr().cast::<c_char>().cast_mut().cast::<c_void>(),
        };
        let mut pamh: *mut PamHandle = ptr::null_mut();
        // SAFETY: `service`/`user`/`secret` are live NUL-terminated
        // `CStr`s for the whole call; `&conversation` names a stack
        // struct that outlives `pam_authenticate` below — the only
        // call that can invoke the callback and dereference
        // `appdata_ptr`; `&mut pamh` is a valid out-pointer libpam
        // writes on success.
        let mut result =
            unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conversation, &mut pamh) };
        if result == PAM_SUCCESS {
            // SAFETY: `pamh` is a live handle returned by the
            // successful `pam_start` above. `conversation` and the
            // secret its `appdata_ptr` names both outlive this call —
            // the only point the callback can run.
            result = unsafe { pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK) };
        }
        if !pamh.is_null() {
            // SAFETY: `pamh` came from `pam_start` and has not been
            // ended yet; upstream passes the result through as
            // `pam_status` verbatim, so a failed authentication is
            // recorded in the handle's closing status exactly as the
            // C shim records it.
            let _ = unsafe { pam_end(pamh, result) };
        }
        result
    }

    #[cfg(test)]
    mod tests {
        //! The conversation callback, exercised directly — the same
        //! `struct pam_message` array libpam would hand it. Every test
        //! frees the response array exactly as libpam would
        //! (`free(resp[i].resp)` per non-NULL entry, then `free(resp)`).

        use super::*;
        use std::ffi::CString;

        const PASSWORD: &CStr = c"s3cret-phrase";

        fn call_conversation(styles: &[c_int]) -> (c_int, *mut PamResponse) {
            let text = CString::new("prompt: ").unwrap();
            let messages: Vec<PamMessage> = styles
                .iter()
                .map(|&s| PamMessage {
                    msg_style: s,
                    msg: text.as_ptr(),
                })
                .collect();
            let ptrs: Vec<*const PamMessage> = messages.iter().map(|m| m as *const _).collect();
            let mut responses: *mut PamResponse = ptr::null_mut();
            // SAFETY: `ptrs` names a live array of `len` message
            // pointers, `text` outlives the call, `PASSWORD` is a live
            // NUL-terminated static, and `responses` is a valid
            // out-pointer — the same contract libpam holds the
            // callback to.
            let rc = unsafe {
                conversation(
                    c_int::try_from(styles.len()).unwrap(),
                    ptrs.as_ptr(),
                    &mut responses,
                    PASSWORD.as_ptr().cast_mut().cast::<c_void>(),
                )
            };
            (rc, responses)
        }

        /// Free a response array the way libpam would, so tests do not
        /// leak: release each non-NULL `resp` then the array.
        ///
        /// # Safety
        /// `responses` must be a `calloc`ed array of `count` entries
        /// returned by `call_conversation`, or NULL.
        unsafe fn free_all(responses: *mut PamResponse, count: usize) {
            unsafe { free_responses(responses, c_int::try_from(count).unwrap()) };
        }

        /// `PAM_PROMPT_ECHO_OFF` is the only prompt answered — and it
        /// is answered with a `strdup`ed copy of the secret.
        #[test]
        fn echo_off_prompt_is_answered_with_the_secret() {
            let (rc, responses) = call_conversation(&[PAM_PROMPT_ECHO_OFF]);
            assert_eq!(rc, PAM_SUCCESS);
            assert!(!responses.is_null());
            // SAFETY: one entry, calloc'd then filled by the callback.
            let answer = unsafe { (*responses).resp };
            assert!(!answer.is_null());
            // SAFETY: `answer` is the `strdup`ed copy just asserted
            // non-NULL.
            assert_eq!(unsafe { CStr::from_ptr(answer) }, PASSWORD);
            // SAFETY: the array came from call_conversation.
            unsafe { free_all(responses, 1) };
        }

        /// `PAM_PROMPT_ECHO_ON` is refused outright: no data leaves,
        /// the conversation fails — the fail-closed rule.
        #[test]
        fn echo_on_prompt_is_refused() {
            let (rc, responses) = call_conversation(&[PAM_PROMPT_ECHO_ON]);
            assert_eq!(rc, PAM_CONV_ERR);
            assert!(responses.is_null());
        }

        /// `PAM_TEXT_INFO` and `PAM_ERROR_MSG` are tolerated but carry
        /// no response data — upstream's exact contract: an
        /// informational line from a module must not fail a legitimate
        /// authentication, and must never be answered either.
        #[test]
        fn informational_messages_are_tolerated_without_data() {
            let (rc, responses) = call_conversation(&[PAM_TEXT_INFO, PAM_ERROR_MSG]);
            assert_eq!(rc, PAM_SUCCESS);
            assert!(!responses.is_null());
            for i in 0..2usize {
                // SAFETY: `responses` is a two-entry array.
                let entry = unsafe { (*responses.add(i)).resp };
                assert!(entry.is_null(), "informational message {i} got data");
            }
            // SAFETY: the array came from call_conversation.
            unsafe { free_all(responses, 2) };
        }

        /// An unknown `msg_style` fails closed, and a single bad
        /// message poisons the whole conversation even when earlier
        /// prompts were answerable.
        #[test]
        fn unknown_and_mixed_styles_fail_closed() {
            let (rc, responses) = call_conversation(&[99]);
            assert_eq!(rc, PAM_CONV_ERR);
            assert!(responses.is_null());

            let (rc, responses) = call_conversation(&[PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON]);
            assert_eq!(rc, PAM_CONV_ERR);
            assert!(responses.is_null());
        }

        /// The malformed-call cases: negative count and NULL pointers
        /// are conversation errors, never reads.
        #[test]
        fn malformed_calls_are_conversation_errors() {
            let mut responses: *mut PamResponse = ptr::null_mut();
            // SAFETY: deliberately malformed arguments — the callback
            // must refuse before touching them.
            let rc = unsafe { conversation(-1, ptr::null(), &mut responses, ptr::null_mut()) };
            assert_eq!(rc, PAM_CONV_ERR);
        }

        /// The whole `pam_start` → `pam_authenticate` → `pam_end`
        /// chain against the live libpam: a service that is not
        /// configured must never produce `PAM_SUCCESS` — authentication
        /// fails closed. Skips only if libpam itself is absent, which
        /// would have failed the link step, so this runs everywhere
        /// the crate builds.
        #[test]
        fn unconfigured_service_never_authenticates() {
            let service = CString::new("central-no-such-service-t5").unwrap();
            let user = CString::new("central-no-such-user-t5").unwrap();
            let secret = CString::new("wrong").unwrap();
            let result = authenticate(&service, &user, &secret);
            assert_ne!(
                result, PAM_SUCCESS,
                "an unconfigured PAM service produced PAM_SUCCESS"
            );
        }

        /// Struct layout pins — the FFI structs are the C ABI, not a
        /// Rust choice: a layout drift is a silent memory corruption
        /// in the conversation.
        #[test]
        fn pam_struct_layouts_match_the_c_abi() {
            assert_eq!(size_of::<PamMessage>(), 16);
            assert_eq!(size_of::<PamResponse>(), 16);
            assert_eq!(size_of::<PamConv>(), 16);
            assert_eq!(align_of::<PamMessage>(), align_of::<usize>());
            assert_eq!(align_of::<PamResponse>(), align_of::<usize>());
            assert_eq!(align_of::<PamConv>(), align_of::<usize>());
        }
    }
}

// ---------------------------------------------------------------------------
// `clone3` + child trampoline — the one place a namespaced,
// credential-dropped child process is created (R5 task 9 / A06). The
// safe front door is `sys::spawn::spawn_namespaced`; everything here
// is POD so nothing but plain C values crosses the clone.
// ---------------------------------------------------------------------------

/// Everything the child trampoline needs. Pointer fields carry the
/// `execve` contract: they must name NUL-terminated strings and
/// NUL-terminated pointer vectors that outlive the `clone3_exec` call
/// (they do — `sys::spawn` builds them from `CString`s on the parent
/// stack, which the child reads through shared copy-on-write pages).
pub(crate) struct CloneExecSpec {
    /// `clone_args.flags` — the `CLONE_NEW*` create set, plus
    /// `CLONE_INTO_CGROUP` when `cgroup_fd` is not `-1` (the caller
    /// ORs the flag itself).
    pub clone_flags: u64,
    /// The cgroup-v2 directory descriptor the child is born into, or -1.
    pub cgroup_fd: i32,
    /// Extra `CLONE_NEW*` bits the child `unshare`s itself pre-exec —
    /// upstream `SysProcAttr.Unshareflags`. `0` skips the call.
    pub unshare_flags: u64,
    /// `setuid`/`setgid` target — the `central-agent` identity.
    pub uid: u32,
    /// `setgid` target.
    pub gid: u32,
    /// `PR_SET_PDEATHSIG` value — upstream's `SIGKILL`; `0` disables
    /// the prctl and its liveness check.
    pub pdeathsig: i32,
    /// The parent's pid at clone time — the post-`prctl` `getppid`
    /// compare that closes the parent-died-before-prctl race.
    pub parent_pid: i32,
    /// `RLIMIT_NOFILE` soft+hard to install; `0` keeps the inherited
    /// limit.
    pub nofile: u64,
    /// `execve` program path — NUL-terminated, live past the call.
    pub program: *const libc::c_char,
    /// NUL-terminated argv/envp pointer vectors — `execve`'s own
    /// contract.
    pub argv: *const *const libc::c_char,
    /// NUL-terminated envp pointer vector.
    pub envp: *const *const libc::c_char,
    /// The error-report pipe's write end (`O_CLOEXEC`) — the one
    /// descriptor the `close_range` sweep spares; `execve` closes it.
    pub err_fd: i32,
}

/// Report `errno` on the error pipe and `_exit` — the child's only
/// channel back to the parent when a setup step or `execve` itself
/// fails. Called in the child only.
fn child_fail(err_fd: i32, error: i32) -> ! {
    // SAFETY: `err_fd` is this child's own descriptor; `error` names a
    // 4-byte int for `write`. `write` and `_exit` are async-signal-safe;
    // a short or failed write is unrecoverable — the exit happens either
    // way, which is the fail-closed property the parent relies on (its
    // read then sees a short frame or EOF, never a false success).
    unsafe {
        let _ = libc::write(err_fd, std::ptr::from_ref(&error).cast::<libc::c_void>(), 4);
        libc::_exit(127);
    }
}

/// `close_range(first, last, 0)` — via `SYS_close_range` directly so no
/// glibc-version symbol is needed. Fails the child on a real error —
/// a descriptor that survives the sweep is a containment breach.
fn close_range_or_fail(err_fd: i32) {
    let sweep = |first: u32, last: u32| -> Result<(), i32> {
        if first > last {
            return Ok(());
        }
        // SAFETY: closes only this child's own descriptors; no borrowed
        // memory, no shared state.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_errno().raw_os_error())
        }
    };
    // `err_fd` is the one fd kept until execve's CLOEXEC clears it; the
    // sweep brackets it on both sides.
    let kept = err_fd.max(0) as u32;
    if kept > 3
        && let Err(e) = sweep(3, kept - 1)
    {
        child_fail(err_fd, e);
    }
    if let Err(e) = sweep(kept.saturating_add(1), u32::MAX) {
        child_fail(err_fd, e);
    }
}

/// The post-clone child half — upstream `SysProcAttr` realized as the
/// exact sequence Go's `forkAndExecInChild1` runs:
///
/// `unshare(Unshareflags)` + the `MS_REC|MS_PRIVATE` `/` remount
/// upstream pairs with `CLONE_NEWNS` → `setgroups(0)` (the credential
/// drop must not keep root's supplementary groups) → `setgid`/`setuid`
/// (`Credential`) → `PR_SET_PDEATHSIG` + `getppid` liveness check
/// (`Pdeathsig`, with the died-before-prctl race closed; the compare
/// is skipped under `CLONE_NEWPID`, where the kernel hides the outer
/// parent by design — `docs/internal/tasks/r5-t9-newpid-pdeathsig.md`)
/// → `setpgid` (`Setpgid`) → `TIOCNOTTY` on the inherited stdin
/// (`Noctty`, result ignored where upstream fails on ENOTTY —
/// deliberately, for the ctty-less daemon shape) → stdin `/dev/null`,
/// stdout ← stderr (`cmd.Stdin = nil`, `Stdout = Stderr = os.Stderr`)
/// → `RLIMIT_NOFILE` → `close_range` fd sweep → `execve`.
///
/// Only async-signal-safe libc entry points run in the child — no
/// allocation, no locks, no Rust runtime — on the child's own
/// copy-on-write pages. Every failure reports its errno on `err_fd`
/// and `_exit(127)`s: a partial sandbox can never exec.
fn child_exec(spec: &CloneExecSpec) -> ! {
    macro_rules! step {
        ($call:expr) => {
            // SAFETY: each call takes only POD/spec fields or string
            // literals; the child runs alone on its own address space
            // until execve replaces it.
            if unsafe { $call } != 0 {
                child_fail(spec.err_fd, last_errno().raw_os_error());
            }
        };
    }

    if spec.unshare_flags != 0 {
        // Truncating a u64 that only ever holds 32-bit CLONE_NEW* bits
        // is lossless — `NamespaceFlags` cannot carry anything else.
        step!(libc::unshare(spec.unshare_flags as libc::c_int));
        // Upstream `forkAndExecInChild1`: the kernel's `unshare` does
        // not unshare mount points mounted `--shared` — and systemd
        // mounts `/` shared (debian bug 739593) — so a `CLONE_NEWNS`
        // unshare must be followed by `mount(NULL, "/", NULL,
        // MS_REC|MS_PRIVATE)`. Without it every mount the child makes
        // propagates back into the host's mount table.
        // SAFETY: `mount` takes literals only — none, "/", none,
        // flags, none — the exact `SYS_MOUNT` shape upstream emits.
        if spec.unshare_flags & u64::from(libc::CLONE_NEWNS as u32)
            == u64::from(libc::CLONE_NEWNS as u32)
        {
            step!(libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null()
            ));
        }
    }
    // Root's supplementary groups must never survive into the child.
    // Upstream runs `setgroups(0)` whenever the spawn carried a
    // `Credential` — the kernel's own EPERM gate on an unprivileged
    // `setgroups` is what makes that unconditional call safe, not a
    // reason to keep a privileged supplementary set. Our spec always
    // carries a target identity, so the gate is privilege-based: a
    // still-root parent (the launcher's contract) drops groups even
    // on a same-uid spawn; an unprivileged parent launching a
    // same-identity child is the one narrow case where `setgroups`
    // could only EPERM — it has no supplementary set beyond its own
    // to shed, so skipping it loses nothing.
    // SAFETY: `getuid`/`getgid`/`geteuid` cannot fail.
    let identity_differs = unsafe { spec.uid != libc::getuid() || spec.gid != libc::getgid() };
    let privileged = unsafe { libc::geteuid() } == 0;
    if identity_differs || privileged {
        step!(libc::setgroups(0, std::ptr::null()));
        step!(libc::setgid(spec.gid));
        step!(libc::setuid(spec.uid));
    }
    if spec.pdeathsig != 0 {
        step!(libc::prctl(
            libc::PR_SET_PDEATHSIG,
            spec.pdeathsig as libc::c_ulong,
            0,
            0,
            0
        ));
        // The Pdeathsig race: the parent exited between clone and this
        // prctl, so the kernel never armed a death signal — `getppid`
        // would now report a reparent. Go's forkExec performs the same
        // check and aborts the child — but only where the child can
        // see the parent: under `CLONE_NEWPID` this child is PID 1 of
        // the new namespace, the kernel reports `getppid() == 0` for a
        // namespace root, and the outer parent is never observable —
        // upstream's compare would condemn every sandboxed child.
        // Skipping the userspace compare only under NEWPID loses no
        // protection: the kernel tracks the real outer-namespace
        // parent and still delivers the armed signal when it dies.
        // SAFETY: `getppid` has no failure mode.
        let new_pid_ns = spec.clone_flags & u64::from(libc::CLONE_NEWPID as u32) != 0;
        if !new_pid_ns && unsafe { libc::getppid() } != spec.parent_pid {
            child_fail(spec.err_fd, libc::ESRCH);
        }
    }
    step!(libc::setpgid(0, 0));
    // `Noctty` — disassociate the controlling terminal. Upstream does
    // NOT ignore this ioctl: `forkAndExecInChild1` aborts the child on
    // `err1 != 0`, so a spawn whose stdin already has no controlling
    // terminal — the daemon launch shape, where the kernel answers
    // ENOTTY — would die outright. This implementation deliberately
    // ignores the result: the detach is best-effort where upstream's
    // check is wrong for a ctty-less daemon, and fd 0 is replaced by
    // /dev/null immediately below, making the observed state identical
    // whether or not a controlling tty was there to release.
    // SAFETY: fd 0 is the child's own; TIOCNOTTY takes no memory.
    unsafe {
        libc::syscall(libc::SYS_ioctl, 0i32, libc::TIOCNOTTY, 0i32);
    }
    // `cmd.Stdin = nil` → stdin is /dev/null; `Stdout = os.Stderr`,
    // `Stderr = os.Stderr` → both point at the inherited stderr.
    // SAFETY: `open`/`dup2`/`close` take literals only.
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if devnull < 0 {
        child_fail(spec.err_fd, last_errno().raw_os_error());
    }
    // SAFETY: `devnull` was just proven open.
    if unsafe { libc::dup2(devnull, 0) } < 0 {
        child_fail(spec.err_fd, last_errno().raw_os_error());
    }
    if devnull != 0 {
        // SAFETY: `devnull` is open and no longer needed at its own slot.
        unsafe { libc::close(devnull) };
    }
    // SAFETY: fds 1 and 2 are the child's own standard streams.
    if unsafe { libc::dup2(2, 1) } < 0 {
        child_fail(spec.err_fd, last_errno().raw_os_error());
    }
    if spec.nofile > 0 {
        let lim = libc::rlimit {
            rlim_cur: spec.nofile,
            rlim_max: spec.nofile,
        };
        // SAFETY: `lim` is a live rlimit for the duration of the call.
        step!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim));
    }
    close_range_or_fail(spec.err_fd);
    // SAFETY: `program`/`argv`/`envp` satisfy execve's contract — the
    // caller guaranteed NUL-terminated strings and NULL-terminated
    // vectors that outlive the clone.
    unsafe { libc::execve(spec.program, spec.argv, spec.envp) };
    child_fail(spec.err_fd, last_errno().raw_os_error());
}

/// `clone3` with `exit_signal = SIGCHLD`, then run [`child_exec`] in
/// the child. Returns the child's pid to the parent.
///
/// # Errors
/// `Errno` of the `clone3` failure — `EPERM` without `CAP_SYS_ADMIN`
/// for the namespace set, `EINVAL` for a flag combination the kernel
/// rejects (`sys::spawn` maps the `CLONE_INTO_CGROUP`-unknown case to
/// its `cgroup.procs` fallback).
pub(crate) fn clone3_exec(spec: &CloneExecSpec) -> Result<libc::pid_t, Errno> {
    // SAFETY: a zeroed clone_args — every field the kernel does not
    // read stays zero, per clone3(2)'s contract.
    let mut args: libc::clone_args = unsafe { std::mem::zeroed() };
    args.flags = spec.clone_flags;
    // SIGCHLD keeps the child waitpid-able exactly like a fork/exec —
    // upstream's `cmd.Wait` shape.
    args.exit_signal = u64::from(libc::SIGCHLD as u32);
    if spec.cgroup_fd >= 0 {
        args.cgroup = spec.cgroup_fd as u64;
    }
    // SAFETY: `args` names a live clone_args for the syscall's
    // duration. clone3 with no `stack`/`pidfd`/`set_tid` fields is the
    // fork form — the child returns from the call on a private copy of
    // this stack and reads `spec` through shared COW pages (the same
    // contract raw clone + child-fn carries; every pointer `spec`
    // holds was caller-proven live). No parent memory is mutated after
    // clone by either side except through spec reads.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::from_ref(&args),
            size_of::<libc::clone_args>(),
        )
    };
    if pid < 0 {
        return Err(last_errno());
    }
    if pid == 0 {
        child_exec(spec);
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(pid as libc::pid_t)
}

/// `SysProcAttr.Credential` for a plain `std::process::Command`:
/// `setgroups(0)` → `setgid(gid)` → `setuid(uid)` in the child — the
/// same three-call sequence `child_exec` runs for the namespaced
/// spawn (root's supplementary groups must never survive), installed
/// through `pre_exec` because `CommandExt::pre_exec` is `unsafe` and
/// every caller of this wrapper lives under `forbid(unsafe_code)`.
/// The helper's managed-browser launch uses it to drop to the locked
/// `central-browser` identity (R5 task 14).
pub(crate) fn command_run_as(cmd: &mut std::process::Command, uid: u32, gid: u32) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs only in the post-fork child before
    // exec; the three calls are async-signal-safe libc entry points
    // on the child's own copy-on-write pages — the exact sequence
    // `child_exec` audits above.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    };
}

/// `SysProcAttr{Setpgid, Pdeathsig}` plus the fd-3 passfile handoff for
/// the pinned `pg_dump`/`pg_restore` invocations (upstream
/// `internal/adapter/backup/pgdump_linux.go` and `pgrestore_linux.go`).
/// The post-fork child runs, in order:
///
///   1. `setpgid(0, 0)` — a private process group so `Close`/settle can
///      `kill(-pid)` the whole tree (`killpg` also lands on any
///      descendant that inherited the dump pipe).
///   2. `prctl(PR_SET_PDEATHSIG, SIGKILL)` — a lost adapter cannot
///      strand a live `central_runtime`/`central_migration` credential
///      or a half-finished destructive restore.
///   3. `getppid() != parent_pid` → `kill(getpid(), SIGKILL)` — closes
///      the fork/exec race where the parent already died and the death
///      signal therefore never fires.
///   4. `dup2(passfile_fd, 3)` — `PGPASSFILE=/proc/self/fd/3`;
///      `dup2` clears `CLOEXEC` so fd 3 alone survives `execve` (the
///      broker descriptor itself is `O_CLOEXEC` and dies at exec).
///
/// Installed through `pre_exec` because `CommandExt::pre_exec` is
/// `unsafe` and every caller lives under `forbid(unsafe_code)`.
///
/// SAFETY: the closure runs only in the post-fork child before exec;
/// every call is an async-signal-safe libc entry point operating on
/// the child's own copy-on-write pages — the same audit standard as
/// `child_exec`/`command_run_as` above. `passfile_fd` is `RawFd`: the
/// parent's `File` is held alive by the caller until `spawn` returns,
/// then closed immediately so only the child's fd-3 copy remains.
pub(crate) fn pg_tool_command(
    cmd: &mut std::process::Command,
    passfile_fd: std::os::fd::RawFd,
    parent_pid: u32,
) {
    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(move || {
            // 1. Private process group.
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // 2. Parent-death signal.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // 3. Race check — the parent may already have exited
            //    between fork and prctl.
            if libc::getppid() as u32 != parent_pid {
                libc::kill(libc::getpid(), libc::SIGKILL);
                return Err(std::io::Error::other("parent exited"));
            }
            // 4. fd 3 passfile handoff. `dup2` clears `CLOEXEC` on the
            //    copy; when the broker descriptor already happens to
            //    be fd 3 there is no copy to make — its own `CLOEXEC`
            //    must be cleared explicitly or `execve` drops it.
            if passfile_fd == 3 {
                if libc::fcntl(3, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(passfile_fd, 3) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    };
}
