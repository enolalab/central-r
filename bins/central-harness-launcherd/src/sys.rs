//! Audited syscall boundary (workflow §5.2).
//!
//! Every `unsafe` of this binary lives behind a named safe wrapper here —
//! the sites rustix 1.1 has no safe API for: `fork`/`execve`, the `clone3`
//! args block, signal handlers and mask operations, `kill(-1)`, NSS
//! lookups (`getpwnam`/`getgrnam`), `close_range`, `dup2`/`dup3` to fixed
//! descriptor numbers, `fcntl` status flags, the `mount_setattr` call,
//! the Landlock syscalls and `unsetenv`. The raw-fd ownership bridges
//! ([`borrow`]) are here too so the rest of the crate can
//! stay free of `unsafe` entirely.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::os::unix::io::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

use rustix::io::Errno;

/// The result of a successful [`fork`].
pub enum Fork {
    /// In the parent: the child's pid.
    Parent(rustix::process::Pid),
    /// In the child.
    Child,
}

/// `fork(2)`. The child must run only the pure-syscall path and end in
/// [`exit`] — the caller guarantees it (the monitor, the init and the
/// cleaners never return to Rust-managed state).
pub fn fork() -> Result<Fork, Errno> {
    // SAFETY: plain fork; the child path is documented above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        Err(Errno::from_io_error(&std::io::Error::last_os_error()).unwrap_or(Errno::INVAL))
    } else if pid == 0 {
        Ok(Fork::Child)
    } else {
        // SAFETY: `pid` is a live child pid from fork.
        Ok(Fork::Parent(unsafe {
            rustix::process::Pid::from_raw_unchecked(pid)
        }))
    }
}

/// Wrap a raw pid (a forked child's) as a `Pid` for the rustix APIs.
pub fn pid_from_raw(pid: i32) -> rustix::process::Pid {
    // SAFETY: call sites hand over only live child pids.
    unsafe { rustix::process::Pid::from_raw_unchecked(pid) }
}

/// `fcntl(fd, F_DUPFD_CLOEXEC, min)` — duplicate to the lowest free
/// descriptor at or above `min`, close-on-exec. rustix has no wrapper.
pub fn dupfd_cloexec(fd: RawFd, min: RawFd) -> Result<OwnedFd, Errno> {
    // SAFETY: fcntl on an open descriptor; the result is owned.
    let r = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, min) };
    if r < 0 {
        return Err(last_errno());
    }
    // SAFETY: `r` is a fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// `execve(2)` — never returns on success.
pub fn execve(path: &CStr, argv: &[*const libc::c_char], envp: &[*const libc::c_char]) -> Errno {
    // SAFETY: the caller guarantees `argv`/`envp` are NULL-terminated
    // pointer arrays to NUL-terminated strings; they are built as such in
    // session.rs right before this call.
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

/// `kill(-1, sig)` — every process the caller may signal except itself.
/// Used by the namespace init to forward SIGTERM to the whole tree.
pub fn kill_all(sig: i32) -> Result<(), Errno> {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    if unsafe { libc::kill(-1, sig) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `kill(pid, sig)` for a raw pid (the monitor records its init's).
pub fn kill_pid(pid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    if unsafe { libc::kill(pid, sig) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `kill(-pgid, sig)` for a raw process-group id (the no-isolation
/// harness's own group stands in for its scope).
#[cfg(feature = "test-build")]
pub fn kill_pgroup(pgid: i32, sig: i32) -> Result<(), Errno> {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    if unsafe { libc::kill(-pgid, sig) } != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `kill(-pgid, 0)`/EPERM probe — "the group still has a member".
#[cfg(feature = "test-build")]
pub fn pgroup_alive(pgid: i32) -> bool {
    // SAFETY: a plain pid/signo pair; no memory is shared.
    unsafe { libc::kill(-pgid, 0) == 0 || *libc::__errno_location() == libc::EPERM }
}

/// `pidfd_send_signal(pidfd, sig, NULL, 0)` — the monitor's SIGTERM/
/// SIGKILL of its namespace init.
pub fn pidfd_send_signal(pidfd: RawFd, sig: i32) -> Result<(), Errno> {
    // SAFETY: `pidfd` is an open pidfd; `sig` a signal number.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
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

/// `prctl(PR_SET_CHILD_SUBREAPER, 1)` — the monitor and the no-isolation
/// init reap the detached grandchildren of their tree. rustix's wrapper
/// takes a pid where upstream's ABI is a boolean flag, so the call sits
/// here verbatim.
pub fn set_child_subreaper() {
    // SAFETY: a flag prctl; no memory is shared.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
}

/// `setpgid(0, 0)` — the no-isolation harness's own process group stands
/// in for its scope cgroup.
#[cfg(feature = "test-build")]
pub fn set_pgroup_self() {
    // SAFETY: own pid, own pgroup.
    unsafe { libc::setpgid(0, 0) };
}

/// `setpgid(pid, pid)` — the init pins its freshly forked harness's
/// group in a no-isolation build.
#[cfg(feature = "test-build")]
pub fn set_pgroup(pid: i32) {
    // SAFETY: a child pid we own.
    unsafe { libc::setpgid(pid, pid) };
}

/// `close_range(first, ~0U, 0)`, with the upstream descriptor-loop
/// fallback for kernels without it (upstream `chl_close_from`).
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

/// `dup2(old, new)` into a fixed descriptor number.
pub fn dup2(old: RawFd, new: RawFd) -> Result<(), Errno> {
    // SAFETY: plain descriptor numbers; the caller drops the old one.
    if unsafe { libc::dup2(old, new) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `dup3(old, new, O_CLOEXEC)` into a fixed descriptor number.
pub fn dup3_cloexec(old: RawFd, new: RawFd) -> Result<(), Errno> {
    // SAFETY: plain descriptor numbers; the caller drops the old one.
    if unsafe { libc::dup3(old, new, libc::O_CLOEXEC) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `fcntl(fd, F_SETFL, old | O_NONBLOCK)` — the control sockets' daemon
/// end must never block (upstream: a wedged monitor never stalls the loop).
pub fn set_nonblock(fd: RawFd) -> Result<(), Errno> {
    // SAFETY: fcntl on an open descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(last_errno());
    }
    // SAFETY: fcntl on an open descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `close(2)` on a raw fd — a no-op on an already-closed number.
pub fn close(fd: RawFd) {
    // SAFETY: closing a descriptor number is harmless.
    unsafe { libc::close(fd) };
}

/// Borrow a fixed, always-open descriptor (0-4, and the ones the monitor
/// and init place there) so the safe rustix APIs can take it.
pub fn borrow(fd: RawFd) -> BorrowedFd<'static> {
    // SAFETY: the call sites use this only for descriptors the process
    // keeps open for its whole life (0-4 in monitor/init, 2 for logging).
    unsafe { BorrowedFd::borrow_raw(fd) }
}

/// `unsetenv(3)` for the socket-activation variables.
pub fn unsetenv(name: &CStr) {
    // SAFETY: single-threaded at this point (start-up); the name is a
    // valid NUL-terminated string.
    unsafe { libc::unsetenv(name.as_ptr()) };
}

/// One `passwd` record, reduced to what the daemon needs.
pub struct Passwd {
    pub uid: u32,
    pub gid: u32,
    pub name: CString,
    pub home: CString,
}

/// `getpwnam(3)` — the operator and runtime user lookups.
pub fn getpwnam(name: &CStr) -> Option<Passwd> {
    // SAFETY: getpwnam returns a thread-static record; we copy the four
    // fields out before returning. Single-threaded here.
    let pw = unsafe { libc::getpwnam(name.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // SAFETY: `pw` is a valid passwd record (checked non-null above).
    let (uid, gid, pname, dir) = unsafe {
        (
            (*pw).pw_uid,
            (*pw).pw_gid,
            CStr::from_ptr((*pw).pw_name).to_owned(),
            CStr::from_ptr((*pw).pw_dir).to_owned(),
        )
    };
    Some(Passwd {
        uid,
        gid,
        name: pname,
        home: dir,
    })
}

/// `getgrnam(3)` — the `tty` group for the private devpts.
pub fn getgrnam(name: &CStr) -> Option<u32> {
    // SAFETY: getgrnam returns a thread-static record; read one field.
    let gr = unsafe { libc::getgrnam(name.as_ptr()) };
    // SAFETY: `gr` checked non-null.
    if gr.is_null() {
        None
    } else {
        Some(unsafe { (*gr).gr_gid })
    }
}

/// Install `handler` as `sig`'s action with an empty mask.
///
/// # Safety contract
/// `handler` must be an `extern "C"` function (or `SIG_DFL`/`SIG_IGN`).
/// The handlers installed by this daemon only set an atomic flag — safe
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

/// `sigemptyset`/`sigfillset`-style empty set.
pub fn sig_empty_set() -> libc::sigset_t {
    // SAFETY: zeroed sigset_t then sigemptyset — trivially valid.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    set
}

/// `sigaddset(&mut set, sig)`.
pub fn sig_add(set: &mut libc::sigset_t, sig: libc::c_int) {
    // SAFETY: `set` is a live sigset_t.
    unsafe { libc::sigaddset(set, sig) };
}

/// `sigprocmask(how, set, NULL)`.
pub fn sig_mask(how: libc::c_int, set: &libc::sigset_t) {
    // SAFETY: `set` is a live sigset_t.
    unsafe { libc::sigprocmask(how, set, std::ptr::null_mut()) };
}

/// `sigwaitinfo(set, &mut info)` — returns the signal number.
pub fn sig_wait(set: &libc::sigset_t) -> libc::c_int {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` and `info` are live objects.
    unsafe { libc::sigwaitinfo(set, &mut info) }
}

/// `signal(s, SIG_DFL)` for every signal — the harness resets its whole
/// disposition table before exec.
pub fn reset_all_signals() {
    for s in 1..libc::SIGRTMAX() {
        // SAFETY: installing SIG_DFL is always sound.
        unsafe { libc::signal(s, libc::SIG_DFL) };
    }
}

/// `poll(NULL, 0, ms)` — the bounded waits of cgroup/monitor code.
pub fn sleep_ms(ms: i32) {
    // SAFETY: no fds, no memory shared.
    unsafe { libc::poll(std::ptr::null_mut(), 0, ms) };
}

/// `SYS_mount_setattr` — rustix has no safe wrapper for it. Marks the
/// mount the O_PATH-capable `tree` descriptor refers to read-only.
pub fn mount_setattr_readonly(tree: RawFd) -> Result<(), Errno> {
    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }
    let attr = MountAttr {
        attr_set: libc::MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: `attr` is the kernel's mount_attr layout (linux/mount.h);
    // `tree` is an open descriptor for a mount.
    let r = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            &attr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if r != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// Landlock (decision 7): the ABI probe and the domain that scopes the
/// harness off abstract Unix sockets and signals outside the domain.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `landlock_create_ruleset(NULL, 0, VERSION)` — the kernel's ABI, or 0
/// without Landlock.
pub fn landlock_abi() -> i32 {
    // SAFETY: version probe; no memory touched.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 0 { 0 } else { abi as i32 }
}

/// Scope the caller into a new Landlock domain with no rules, scoped
/// against abstract sockets and foreign signals (upstream
/// `landlock_scope`). Needs NO_NEW_PRIVS or CAP_SYS_ADMIN.
pub fn landlock_scope() -> Result<(), Errno> {
    let attr = LandlockRulesetAttr {
        handled_access_fs: 0,
        handled_access_net: 0,
        scoped: LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
    };
    // SAFETY: `attr` is the kernel's landlock_ruleset_attr layout.
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset < 0 {
        return Err(last_errno());
    }
    // SAFETY: `ruleset` is a live ruleset fd from the call above.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) };
    close(ruleset as RawFd);
    if r != 0 {
        return Err(last_errno());
    }
    Ok(())
}

/// `clone3(2)` with the caller-filled args (the monitor sets flags/pidfd/
/// cgroup). rustix has no safe clone3 API.
pub fn clone3(args: &libc::clone_args) -> Result<i32, Errno> {
    // SAFETY: `args` is the kernel's clone_args layout; the caller fills
    // every field (pidfd pointer is an out-param the kernel writes).
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            args,
            std::mem::size_of::<libc::clone_args>(),
        )
    };
    if pid < 0 {
        return Err(last_errno());
    }
    Ok(pid as i32)
}

/// `readlinkat(fd, "", buf)` — reads the target of the symbolic link an
/// O_PATH|O_NOFOLLOW descriptor refers to (the /dev/ptmx check).
pub fn readlink_fd(fd: RawFd, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: `buf` is writable for its length; empty path on an O_PATH
    // fd is the documented Linux extension.
    let n = unsafe { libc::readlinkat(fd, c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(last_errno());
    }
    Ok(n as usize)
}

/// `path` (NUL-free bytes) as an owned `CString`.
pub fn bytes_cstring(b: &[u8]) -> Option<CString> {
    CString::new(b).ok()
}
