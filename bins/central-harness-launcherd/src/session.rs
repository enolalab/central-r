//! A launch's monitor and init (spec decisions 2, 3, 4, 7 and 8) —
//! upstream `session.c`.
//!
//! The daemon forks one monitor per LAUNCH. The monitor owns the scope
//! from LAUNCH until release: it `clone3`s the init into the scope with
//! new mount, PID and IPC namespaces, answers LAUNCH with the stdio
//! pipe ends and the init's pidfd, answers forwarded ALIVE and KILL,
//! and, once the init has exited and the scope is drained and removed
//! and the daemon has dropped ownership, sends EXIT on the lifeline.
//!
//! The init is PID 1 of the new namespace. As root it builds the mount
//! view, forks the harness (which drops privilege and execs), drops its
//! own privilege, forwards SIGTERM to the namespace, reaps everything
//! and writes the harness's raw wait status to its status channel
//! (fd 3) before it exits; the kernel then kills whatever is left in
//! the namespace.
//!
//! Status channel messages (init -> monitor, one write each):
//!   'R' + i32 harness pid   the view is built and the harness exec'd
//!   'F' + i32 step + i32 errno
//!                           setup failed at that step; nothing runs
//!   'X' + i32 wait status   the harness ended with this raw status
//!
//! Test builds under `CHL_TEST_NO_ISOLATION` skip namespaces, mounts,
//! cgroup placement and the identity change; the harness gets its own
//! process group, which stands in for the scope.

use std::ffi::{CStr, CString};
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use central_adapter_harness::launcher::protocol as wire;
use wire::{Opcode, Reason, Scope};

use rustix::event::Timespec;
use rustix::fs::{CWD, FileType, Mode, OFlags, ResolveFlags, fstat, mkdirat, open};
use rustix::io::{Errno, read, write};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recvmsg, send, sendmsg, socketpair,
};
use rustix::pipe::{PipeFlags, pipe_with};
use rustix::process::{WaitOptions, wait, waitpid};
use rustix::thread::{
    CapabilitiesSecureBits, CapabilitySet, CapabilitySets, capabilities,
    clear_ambient_capability_set, remove_capability_from_bounding_set, set_capabilities,
    set_capabilities_secure_bits, set_no_new_privs, set_thread_groups, set_thread_res_gid,
    set_thread_res_uid,
};

use crate::knobs;
use crate::policy::{self, Config, HarnessEntry, Operator};
use crate::protocol::{
    DROP_AMBIENT, DROP_CAPBSET, DROP_CAPS_LEFT, DROP_CAPSET, DROP_LANDLOCK, DROP_NNP_DUMPABLE,
    DROP_SECUREBITS, DROP_SETGROUPS, DROP_SETID, STEP_ATTACH_ENTRY, STEP_ATTACH_HOME,
    STEP_ATTACH_WORKTREE, STEP_CGROUP_REOPEN, STEP_CHDIR, STEP_CLONE3, STEP_CWD_LENGTH,
    STEP_DEVPTS_CONFIG, STEP_DEVPTS_MOUNT, STEP_DEVPTS_OPEN, STEP_ERROR_PIPE, STEP_EXEC,
    STEP_HARNESS_DROP, STEP_HARNESS_FD, STEP_HARNESS_FORK, STEP_HARNESS_HOME, STEP_HARNESS_REPORT,
    STEP_HIDE_DEV_SHM, STEP_HIDE_HOME_PARENT, STEP_HIDE_ROOT, STEP_HIDE_RUN_USER, STEP_HIDE_TMP,
    STEP_HIDE_VAR_TMP, STEP_INIT_DROP, STEP_INIT_FDS, STEP_INIT_LANDLOCK, STEP_INIT_NNP,
    STEP_LIFELINE_LOST, STEP_MAKE_RO, STEP_MONITOR_FDS, STEP_MONITOR_PIPE, STEP_MOUNT_SLAVE,
    STEP_OPEN_HOME, STEP_PROC_MOUNT, STEP_PTMX_BIND, STEP_SCOPE_OPEN, STEP_SETUP_POLL,
    STEP_SETUP_TIMEOUT, STEP_SOURCE_CLONE, STEP_STATUS_CHANNEL, STEP_WORKTREE_CLONE,
    STEP_WORKTREE_HIDE, STEP_WORKTREE_IDENTITY, STEP_WORKTREE_ROOT, log, log_init_ended, log_step,
};
use crate::sys;

const MAX_PENDING_KILLS: usize = 16;
#[cfg(feature = "test-build")]
const LANDLOCK_MIN_ABI: i32 = 6;

/// Control messages between the daemon and a monitor (a SEQPACKET
/// socketpair). Forwarded requests carry the client connection.
pub const CTL_ALIVE: u8 = b'A';
pub const CTL_KILL: u8 = b'K';
pub const CTL_RELEASE: u8 = b'R';
pub const CTL_RELEASED: u8 = b'a';

const RESOLVE_STRICT: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);
const RESOLVE_NO_SYMLINKS: ResolveFlags =
    ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);

/* ---- the plan (upstream struct chl_plan) ---- */

/// Everything a launch's monitor and init need; the daemon fills it
/// after validation and the monitor inherits it through fork.
pub struct Plan {
    pub scope: Scope,
    pub op: Operator,
    pub config: Config,
    pub harness: HarnessEntry,
    /// Relative to `worktree_root`, or empty for a probe.
    pub workdir: Vec<u8>,
    /// `worktree_root` as validated (`check_home_config`); the init
    /// re-opens it and requires the same identity.
    pub root_dev: u64,
    pub root_ino: u64,
    /// Path to exec inside the view.
    pub program: CString,
    /// argv[0] = program.
    pub argv: Vec<CString>,
    pub envp: Vec<CString>,
    /// The view's devpts gid= (the "tty" group), when the host has one.
    pub tty_gid: Option<u32>,
}

/* ---- small helpers ---- */

fn now_ms() -> i64 {
    // Milliseconds on a process-lifetime monotonic base; every deadline
    // is compared against this same clock inside one process.
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as i64
}

fn ms_timespec(ms: i64) -> Timespec {
    Timespec {
        tv_sec: ms / 1000,
        tv_nsec: (ms % 1000) * 1_000_000,
    }
}

fn write_all(fd: RawFd, buf: &[u8]) -> Result<(), Errno> {
    let b = sys::borrow(fd);
    let mut left = buf;
    while !left.is_empty() {
        match write(b, left) {
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
            Ok(0) => return Err(Errno::IO),
            Ok(n) => left = &left[n..],
        }
    }
    Ok(())
}

/// `read_full` — up to `buf.len()` bytes, stopping early only at EOF.
fn read_full(fd: RawFd, buf: &mut [u8]) -> Result<usize, Errno> {
    let b = sys::borrow(fd);
    let mut got = 0usize;
    while got < buf.len() {
        match read(b, &mut buf[got..]) {
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e),
            Ok(0) => break,
            Ok(n) => got += n,
        }
    }
    Ok(got)
}

/// `chl_send_fds` — a datagram with descriptors attached. On a
/// non-blocking socket it fails at once rather than wait.
pub fn send_fds(sock: RawFd, data: &[u8], fds: &[RawFd]) -> Result<(), Errno> {
    if fds.len() > 4 {
        return Err(Errno::INVAL);
    }
    let borrowed: Vec<BorrowedFd> = fds.iter().map(|fd| sys::borrow(*fd)).collect();
    let iov = [IoSlice::new(data)];
    let mut cmsg_space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = SendAncillaryBuffer::new(&mut cmsg_space);
    if !borrowed.is_empty() {
        control.push(SendAncillaryMessage::ScmRights(&borrowed));
    }
    let sock = sys::borrow(sock);
    loop {
        match sendmsg(sock, &iov, &mut control, SendFlags::NOSIGNAL) {
            Err(Errno::INTR) => continue,
            Ok(sent) if sent == data.len() => return Ok(()),
            Ok(_) => return Err(Errno::IO),
            Err(e) => return Err(e),
        }
    }
}

/// `recv_with_fd` — one control message and at most one descriptor
/// (extras close when the drain drops). Non-blocking.
fn recv_with_fd(sock: RawFd, buf: &mut [u8]) -> Result<(usize, Option<OwnedFd>), Errno> {
    let mut iov = [std::io::IoSliceMut::new(buf)];
    let mut cmsg_space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut cmsg_space);
    let sock = sys::borrow(sock);
    let msg = loop {
        match recvmsg(
            sock,
            &mut iov,
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
        ) {
            Err(Errno::INTR) => continue,
            other => break other,
        }
    }?;
    let mut first: Option<OwnedFd> = None;
    for m in control.drain() {
        if let RecvAncillaryMessage::ScmRights(mut it) = m
            && first.is_none()
        {
            first = it.next();
        }
    }
    Ok((msg.bytes, first))
}

/// `respond` — a fixed 12-byte response on `conn`.
fn respond(conn: RawFd, op: Opcode, status: Reason, p0: u8, code: u16) {
    let r = wire::Response {
        op,
        status,
        alive: p0 != 0 && op == Opcode::Alive,
        exit: wire::Exit {
            code: code as i32,
            signaled: p0 != 0 && op == Opcode::Exit,
        },
    };
    let Ok(frame) = wire::encode_response(&r) else {
        return;
    };
    let _ = send(sys::borrow(conn), &frame, SendFlags::NOSIGNAL);
}

/* ---- Landlock scoping (decision 7, step 6) ---- */

/// `landlock_scope` puts the caller in a new Landlock domain with no
/// filesystem or network rules, scoped so that it can neither connect
/// to an abstract Unix socket nor signal a process created outside the
/// domain. It needs NO_NEW_PRIVS (or CAP_SYS_ADMIN). A no-isolation
/// test build skips it on a kernel below ABI 6; everywhere else a
/// failure is fatal.
fn landlock_scope() -> Result<(), Errno> {
    #[cfg(feature = "test-build")]
    if knobs::no_isolation() && sys::landlock_abi() < LANDLOCK_MIN_ABI {
        return Ok(());
    }
    sys::landlock_scope()
}

/* ---- launch failure diagnostics ---- */

/* The failing step of this process (the monitor, the init or the
 * harness, each its own copy) and the errno there. */
static FAILED_STEP: AtomicI32 = AtomicI32::new(0);
static FAILED_ERR: AtomicI32 = AtomicI32::new(0);

fn fail(step: i32) -> Errno {
    let e = sys::last_errno();
    FAILED_STEP.store(step, Ordering::Relaxed);
    FAILED_ERR.store(e.raw_os_error(), Ordering::Relaxed);
    e
}

fn fail_check(step: i32) -> Errno {
    FAILED_STEP.store(step, Ordering::Relaxed);
    FAILED_ERR.store(0, Ordering::Relaxed);
    Errno::INVAL
}

fn fail_with(step: i32, e: Errno) -> Errno {
    FAILED_STEP.store(step, Ordering::Relaxed);
    FAILED_ERR.store(e.raw_os_error(), Ordering::Relaxed);
    e
}

fn failed() -> (i32, i32) {
    (
        FAILED_STEP.load(Ordering::Relaxed),
        FAILED_ERR.load(Ordering::Relaxed),
    )
}

/* ---- privilege drop (decision 7, steps 2-6) ---- */

/// `drop_privileges` runs the drop sequence. `scope` adds the Landlock
/// domain after NO_NEW_PRIVS: the harness passes true; the init passes
/// false because it scoped itself before it forked the harness.
fn drop_privileges(op: &Operator, scope: bool, base: i32) -> Result<(), Errno> {
    if !knobs::no_isolation() {
        for cap in 0u8..64 {
            let set = CapabilitySet::from_bits_retain(1u64 << cap);
            match remove_capability_from_bounding_set(set) {
                Ok(()) | Err(Errno::INVAL) => {}
                Err(e) => {
                    let _ = fail_with(base + DROP_CAPBSET, e);
                    return Err(e);
                }
            }
        }
    }
    if let Err(e) = clear_ambient_capability_set() {
        let _ = fail_with(base + DROP_AMBIENT, e);
        return Err(e);
    }
    if !knobs::no_isolation() {
        // NOROOT locked and NO_SETUID_FIXUP unset: the setresuid below
        // clears the permitted and effective sets.
        if let Err(e) = set_capabilities_secure_bits(
            CapabilitiesSecureBits::NO_ROOT | CapabilitiesSecureBits::NO_ROOT_LOCKED,
        ) {
            let _ = fail_with(base + DROP_SECUREBITS, e);
            return Err(e);
        }
        if let Err(e) = set_thread_groups(&[]) {
            let _ = fail_with(base + DROP_SETGROUPS, e);
            return Err(e);
        }
    }
    let gid = rustix::process::Gid::from_raw(op.gid);
    let uid = rustix::process::Uid::from_raw(op.uid);
    if let Err(e) = set_thread_res_gid(gid, gid, gid) {
        let _ = fail_with(base + DROP_SETID, e);
        return Err(e);
    }
    if let Err(e) = set_thread_res_uid(uid, uid, uid) {
        let _ = fail_with(base + DROP_SETID, e);
        return Err(e);
    }
    let empty = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    if let Err(e) = set_capabilities(None, empty) {
        let _ = fail_with(base + DROP_CAPSET, e);
        return Err(e);
    }
    match capabilities(None) {
        Err(e) => {
            let _ = fail_with(base + DROP_CAPS_LEFT, e);
            return Err(e);
        }
        Ok(sets)
            if !sets.effective.is_empty()
                || !sets.permitted.is_empty()
                || !sets.inheritable.is_empty() =>
        {
            return Err(fail_check(base + DROP_CAPS_LEFT));
        }
        Ok(_) => {}
    }
    // Decision 7 step 6: DUMPABLE 0 is what matters for the init, which
    // never execs: the harness (same UID, no capabilities) then cannot
    // ptrace it or open /proc/1/fd and /proc/1/mem to forge its status
    // channel. For the harness the flag is moot: its execve resets
    // dumpable to 1. It is set anyway so both run the one sequence.
    if let Err(e) = set_no_new_privs(true) {
        let _ = fail_with(base + DROP_NNP_DUMPABLE, e);
        return Err(e);
    }
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        let _ = fail_with(base + DROP_NNP_DUMPABLE, e);
        return Err(e);
    }
    if scope && let Err(e) = landlock_scope() {
        let _ = fail_with(base + DROP_LANDLOCK, e);
        return Err(e);
    }
    Ok(())
}

/* ---- mount view (decision 8) ---- */

fn open_tree_clone(fd: &OwnedFd) -> Result<OwnedFd, Errno> {
    rustix::mount::open_tree(
        fd,
        "",
        rustix::mount::OpenTreeFlags::OPEN_TREE_CLOEXEC
            | rustix::mount::OpenTreeFlags::OPEN_TREE_CLONE
            | rustix::mount::OpenTreeFlags::AT_EMPTY_PATH,
    )
}

fn attach(tree: impl AsFd, target: impl AsFd) -> Result<(), Errno> {
    rustix::mount::move_mount(
        tree,
        "",
        target,
        "",
        rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH
            | rustix::mount::MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
}

/// `tmpfs_on` mounts a fresh tmpfs on the directory `target` (a
/// descriptor, so no path is resolved again) and returns an O_PATH
/// descriptor of its root.
fn tmpfs_on(target: &OwnedFd, mode: &CStr) -> Result<OwnedFd, Errno> {
    let fs = rustix::mount::fsopen(c"tmpfs", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC)?;
    let mnt = rustix::mount::fsconfig_set_string(&fs, c"mode", mode)
        .and_then(|_| rustix::mount::fsconfig_create(&fs))
        .and_then(|_| {
            rustix::mount::fsmount(
                &fs,
                rustix::mount::FsMountFlags::FSMOUNT_CLOEXEC,
                rustix::mount::MountAttrFlags::MOUNT_ATTR_NOSUID
                    | rustix::mount::MountAttrFlags::MOUNT_ATTR_NODEV,
            )
        })?;
    attach(&mnt, target)?;
    Ok(mnt)
}

fn openat2_beneath(
    dirfd: impl AsFd,
    path: &[u8],
    flags: OFlags,
    resolve: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    use std::os::unix::ffi::OsStrExt;
    // R5 task 14, D5: the `openat2` call itself lives in the shared
    // audited boundary — `resolve_with` is this shim's exact upstream
    // shape (`Mode::empty()`, `CLOEXEC` added inside).
    central_adapter_linux::sys::openat2::resolve_with(
        dirfd,
        std::path::Path::new(std::ffi::OsStr::from_bytes(path)),
        flags,
        resolve,
    )
}

/// `private_devpts` mounts a new devpts instance on /dev/pts and binds
/// its ptmx over /dev/ptmx, so the host's ptys are not in the view
/// while ptys opened inside it still work.
fn private_devpts(p: &Plan) -> Result<(), Errno> {
    let target = match open(
        c"/dev/pts",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(t) => t,
        Err(e) => return Err(fail_with(STEP_DEVPTS_OPEN, e)),
    };
    let fs = match rustix::mount::fsopen(c"devpts", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC) {
        Err(e) => return Err(fail_with(STEP_DEVPTS_CONFIG, e)),
        Ok(f) => f,
    };
    let gid_text = p.tty_gid.map(|g| g.to_string());
    let gid_c = gid_text
        .as_ref()
        .and_then(|g| sys::bytes_cstring(g.as_bytes()));
    let configured = rustix::mount::fsconfig_set_flag(&fs, c"newinstance")
        .and_then(|_| rustix::mount::fsconfig_set_string(&fs, c"ptmxmode", c"0666"))
        .and_then(|_| rustix::mount::fsconfig_set_string(&fs, c"mode", c"0620"))
        .and_then(|_| match &gid_c {
            Some(g) => rustix::mount::fsconfig_set_string(&fs, c"gid", g.as_c_str()),
            None => Ok(()),
        })
        // Caps this instance's pty pool so one session cannot exhaust
        // the shared non-initial devpts allocation.
        .and_then(|_| rustix::mount::fsconfig_set_string(&fs, c"max", c"256"))
        .and_then(|_| rustix::mount::fsconfig_create(&fs));
    if let Err(e) = configured {
        return Err(fail_with(STEP_DEVPTS_CONFIG, e));
    }
    let mnt = match rustix::mount::fsmount(
        &fs,
        rustix::mount::FsMountFlags::FSMOUNT_CLOEXEC,
        rustix::mount::MountAttrFlags::MOUNT_ATTR_NOSUID
            | rustix::mount::MountAttrFlags::MOUNT_ATTR_NOEXEC,
    ) {
        Err(e) => return Err(fail_with(STEP_DEVPTS_MOUNT, e)),
        Ok(m) => m,
    };
    if let Err(e) = attach(&mnt, &target) {
        return Err(fail_with(STEP_DEVPTS_MOUNT, e));
    }
    // /dev/ptmx: a device node gets the new instance's ptmx bound over
    // it; a "pts/ptmx" symlink already leads there.
    let ptmx = match open(
        c"/dev/ptmx",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Err(e) => return Err(fail_with(STEP_PTMX_BIND, e)),
        Ok(f) => f,
    };
    let st = match fstat(&ptmx) {
        Err(e) => return Err(fail_with(STEP_PTMX_BIND, e)),
        Ok(s) => s,
    };
    if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
        let mut link = [0u8; 16];
        let n = sys::readlink_fd(ptmx.as_raw_fd(), &mut link).unwrap_or(0);
        return if n == 8 && link[..8] == *b"pts/ptmx" {
            Ok(())
        } else {
            Err(fail_check(STEP_PTMX_BIND))
        };
    }
    if FileType::from_raw_mode(st.st_mode) != FileType::CharacterDevice {
        return Err(fail_check(STEP_PTMX_BIND));
    }
    let inner = openat2_beneath(
        &mnt,
        b"ptmx",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        RESOLVE_STRICT,
    );
    let tree = inner
        .and_then(|i| open_tree_clone(&i))
        .map_err(|e| fail_with(STEP_PTMX_BIND, e))?;
    attach(&tree, &ptmx).map_err(|e| fail_with(STEP_PTMX_BIND, e))
}

/// `mkdirs_beneath` creates each component of `rel` beneath `dirfd`,
/// which lies on a root-created tmpfs, and returns an O_PATH
/// descriptor of the last one. Every caller binds `rel` well under
/// PATH_MAX (workdir ≤4096, fixed hidden-tree suffixes), so the C
/// PATH_MAX guard has no reachable analogue here.
fn mkdirs_beneath(dirfd: &OwnedFd, rel: &[u8]) -> Result<OwnedFd, Errno> {
    let mut cur = sys::dupfd_cloexec(dirfd.as_raw_fd(), 0)?;
    for part in rel.split(|b| *b == b'/') {
        if part.is_empty() {
            continue;
        }
        let Some(part_c) = sys::bytes_cstring(part) else {
            return Err(Errno::INVAL);
        };
        match mkdirat(&cur, part_c.as_c_str(), Mode::from_bits_retain(0o755)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(e) => return Err(e),
        }
        cur = openat2_beneath(
            &cur,
            part,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            RESOLVE_STRICT,
        )?;
    }
    Ok(cur)
}

/// `open_beneath_hidden` — `path` re-created on the tmpfs root
/// `roots[i]` of the first mounted hidden tree it lies beneath; `None`
/// when it lies beneath none.
fn open_beneath_hidden(
    path: &[u8],
    hidden: &[&[u8]],
    roots: &[Option<OwnedFd>],
) -> Result<Option<OwnedFd>, Errno> {
    for (i, h) in hidden.iter().enumerate() {
        let Some(root_fd) = roots[i].as_ref() else {
            continue;
        };
        if !policy::path_beneath(h, path) {
            continue;
        }
        return mkdirs_beneath(root_fd, &path[h.len() + 1..]).map(Some);
    }
    Ok(None)
}

fn build_view(p: &Plan) -> Result<(), Errno> {
    let c = &p.config;
    let mut trees: Vec<OwnedFd> = Vec::new();
    let mut entries: Vec<usize> = Vec::new();

    // parent = dirname(op.home); home_base = basename.
    let mut parent = p.op.home.clone();
    let slash = parent.iter().rposition(|b| *b == b'/').unwrap_or(0);
    let home_base = parent[slash + 1..].to_vec();
    parent.truncate(slash);

    // The trees a tmpfs replaces, and that tmpfs's root once mounted.
    let hidden: [&[u8]; 6] = [
        b"/root",
        b"/run/user",
        b"/tmp",
        b"/var/tmp",
        b"/dev/shm",
        &parent,
    ];
    let modes: [&CStr; 6] = [c"0700", c"0755", c"1777", c"1777", c"1777", c"0755"];
    let hide_steps = [
        STEP_HIDE_ROOT,
        STEP_HIDE_RUN_USER,
        STEP_HIDE_TMP,
        STEP_HIDE_VAR_TMP,
        STEP_HIDE_DEV_SHM,
        STEP_HIDE_HOME_PARENT,
    ];
    let nhidden = hidden.len();
    let mut roots: Vec<Option<OwnedFd>> = (0..nhidden).map(|_| None).collect();

    let home: Option<OwnedFd>;
    let harness_home: Option<OwnedFd>;
    let home_tree: Option<OwnedFd>;
    let mut wt_tree: Option<OwnedFd> = None;
    let root: Option<OwnedFd>;
    let wt_root: Option<OwnedFd>;

    let mut result: Result<(), Errno> = Ok(());
    'out: {
        // 1. Nothing propagates back to the host.
        if let Err(e) = rustix::mount::mount_change(
            c"/",
            rustix::mount::MountPropagationFlags::DOWNSTREAM
                | rustix::mount::MountPropagationFlags::REC,
        ) {
            result = Err(fail_with(STEP_MOUNT_SLAVE, e));
            break 'out;
        }
        // 2. Open and clone every source before any tmpfs hides it.
        // worktree_root is re-opened the way the daemon validated it
        // and must be the same directory.
        match policy::open_worktree_root(c) {
            Err(e) => {
                result = Err(fail_with(STEP_WORKTREE_ROOT, e));
                break 'out;
            }
            Ok((fd, st)) => {
                if st.st_dev != p.root_dev || st.st_ino != p.root_ino {
                    result = Err(fail_check(STEP_WORKTREE_IDENTITY));
                    break 'out;
                }
                root = Some(fd);
            }
        }
        let Some(root_fd) = root.as_ref() else {
            result = Err(fail_check(STEP_WORKTREE_ROOT));
            break 'out;
        };
        let Some(home_c) = sys::bytes_cstring(&p.op.home) else {
            result = Err(fail_check(STEP_OPEN_HOME));
            break 'out;
        };
        home = match open(
            home_c.as_c_str(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Err(e) => {
                result = Err(fail_with(STEP_OPEN_HOME, e));
                break 'out;
            }
            Ok(h) => Some(h),
        };
        let Some(home_fd) = home.as_ref() else {
            result = Err(fail_check(STEP_OPEN_HOME));
            break 'out;
        };
        harness_home = match openat2_beneath(
            home_fd,
            &p.harness.home_dir,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            RESOLVE_STRICT,
        ) {
            Err(e) => {
                result = Err(fail_with(STEP_HARNESS_HOME, e));
                break 'out;
            }
            Ok(h) => Some(h),
        };
        let Some(hh) = harness_home.as_ref() else {
            result = Err(fail_check(STEP_HARNESS_HOME));
            break 'out;
        };
        home_tree = match open_tree_clone(hh) {
            Err(e) => {
                result = Err(fail_with(STEP_HARNESS_HOME, e));
                break 'out;
            }
            Ok(t) => Some(t),
        };
        for (i, m) in c.mounts.iter().enumerate() {
            if m.harness != p.harness.id {
                continue;
            }
            let src = match openat2_beneath(
                home_fd,
                &m.source,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                RESOLVE_STRICT,
            ) {
                Err(e) => {
                    result = Err(fail_with(STEP_SOURCE_CLONE, e));
                    break 'out;
                }
                Ok(s) => s,
            };
            let tree = match open_tree_clone(&src) {
                Err(e) => {
                    result = Err(fail_with(STEP_SOURCE_CLONE, e));
                    break 'out;
                }
                Ok(t) => t,
            };
            if m.read_only
                && let Err(e) = sys::mount_setattr_readonly(tree.as_raw_fd())
            {
                result = Err(fail_with(STEP_MAKE_RO, e));
                break 'out;
            }
            entries.push(i);
            trees.push(tree);
        }
        if !p.workdir.is_empty() {
            let wt = match openat2_beneath(
                root_fd,
                &p.workdir,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                RESOLVE_STRICT,
            ) {
                Err(e) => {
                    result = Err(fail_with(STEP_WORKTREE_CLONE, e));
                    break 'out;
                }
                Ok(w) => w,
            };
            wt_tree = match open_tree_clone(&wt) {
                Err(e) => {
                    result = Err(fail_with(STEP_WORKTREE_CLONE, e));
                    break 'out;
                }
                Ok(t) => Some(t),
            };
        }
        // 2 (cont). Hide every home, root's home, user runtime dirs and
        // temp, each by a tmpfs mounted on a descriptor. A tree beneath
        // another hidden tree is already on a fresh tmpfs. The fixed
        // system paths are root's; an absent one is skipped.
        for i in 0..nhidden {
            let covered =
                (0..nhidden).any(|j| j != i && policy::path_beneath(hidden[j], hidden[i]));
            if covered {
                continue;
            }
            let target = if i == nhidden - 1 {
                // R5 task 14, D5: the shared audited `openat2` site.
                central_adapter_linux::sys::openat2::resolve_with(
                    CWD,
                    std::path::Path::new(std::ffi::OsStr::from_bytes(hidden[i])),
                    OFlags::PATH | OFlags::DIRECTORY,
                    RESOLVE_NO_SYMLINKS,
                )
            } else {
                let Some(h) = sys::bytes_cstring(hidden[i]) else {
                    result = Err(fail_check(hide_steps[i]));
                    break 'out;
                };
                open(
                    h.as_c_str(),
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
            };
            let target = match target {
                Err(e) if e == Errno::NOENT && i != nhidden - 1 => continue,
                Err(e) => {
                    result = Err(fail_with(hide_steps[i], e));
                    break 'out;
                }
                Ok(t) => t,
            };
            match tmpfs_on(&target, modes[i]) {
                Err(e) => {
                    result = Err(fail_with(hide_steps[i], e));
                    break 'out;
                }
                Ok(r) => roots[i] = Some(r),
            }
        }
        // 3. Hide every other worktree: a tmpfs on the worktree_root
        // descriptor unless it already lies beneath a hidden tree,
        // where its path is re-created on that tmpfs.
        wt_root = match open_beneath_hidden(&c.worktree_root, &hidden, &roots) {
            Err(e) => {
                result = Err(fail_with(STEP_WORKTREE_HIDE, e));
                break 'out;
            }
            Ok(Some(fd)) => Some(fd),
            Ok(None) => match tmpfs_on(root_fd, c"0755") {
                Err(e) => {
                    result = Err(fail_with(STEP_WORKTREE_HIDE, e));
                    break 'out;
                }
                Ok(fd) => Some(fd),
            },
        };
        // 4. A /proc of this PID namespace only, and a devpts of this
        // view only.
        if let Err(e) = rustix::mount::mount(
            c"proc",
            c"/proc",
            c"proc",
            rustix::mount::MountFlags::NOSUID
                | rustix::mount::MountFlags::NODEV
                | rustix::mount::MountFlags::NOEXEC,
            None,
        ) {
            result = Err(fail_with(STEP_PROC_MOUNT, e));
            break 'out;
        }
        if let Err(e) = private_devpts(p) {
            result = Err(e);
            break 'out;
        }
        // 5. The harness home at HOME, on the root-created tmpfs.
        let parent_fd = match open_beneath_hidden(&parent, &hidden[..nhidden - 1], &roots) {
            Err(_) => None,
            Ok(Some(fd)) => Some(fd),
            Ok(None) => roots[nhidden - 1]
                .as_ref()
                .and_then(|r| sys::dupfd_cloexec(r.as_raw_fd(), 0).ok()),
        };
        let home_target = parent_fd.and_then(|fd| mkdirs_beneath(&fd, &home_base).ok());
        let Some(ht) = home_target.as_ref() else {
            result = Err(fail(STEP_ATTACH_HOME));
            break 'out;
        };
        let Some(home_t) = home_tree.as_ref() else {
            result = Err(fail(STEP_ATTACH_HOME));
            break 'out;
        };
        if let Err(e) = attach(home_t, ht) {
            result = Err(fail_with(STEP_ATTACH_HOME, e));
            break 'out;
        }
        // 6. The configured entries, resolved on the harness home by dirfd.
        let Some(home_c2) = sys::bytes_cstring(&p.op.home) else {
            result = Err(fail_check(STEP_ATTACH_ENTRY));
            break 'out;
        };
        let view_home = match open(
            home_c2.as_c_str(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Err(e) => {
                result = Err(fail_with(STEP_ATTACH_ENTRY, e));
                break 'out;
            }
            Ok(v) => v,
        };
        for (ti, &mi) in entries.iter().enumerate() {
            let m = &c.mounts[mi];
            let target = match openat2_beneath(
                &view_home,
                &m.target,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                RESOLVE_STRICT,
            ) {
                Err(e) => {
                    result = Err(fail_with(STEP_ATTACH_ENTRY, e));
                    break 'out;
                }
                Ok(t) => t,
            };
            if let Err(e) = attach(&trees[ti], &target) {
                result = Err(fail_with(STEP_ATTACH_ENTRY, e));
                break 'out;
            }
        }
        // 7. The attempt's worktree at its real path.
        if let Some(wt) = &wt_tree {
            let Some(wtr) = wt_root.as_ref() else {
                result = Err(fail(STEP_ATTACH_WORKTREE));
                break 'out;
            };
            let target = match mkdirs_beneath(wtr, &p.workdir) {
                Err(e) => {
                    result = Err(fail_with(STEP_ATTACH_WORKTREE, e));
                    break 'out;
                }
                Ok(t) => t,
            };
            if let Err(e) = attach(wt, &target) {
                result = Err(fail_with(STEP_ATTACH_WORKTREE, e));
                break 'out;
            }
        }
    }
    result
}

/* ---- the harness process ---- */

/// `harness_fail` sends the harness's failing step and errno to the
/// init (two int32s on the error pipe, fd 3) and exits.
fn harness_fail(fd: RawFd) -> ! {
    let (step, err) = failed();
    let mut msg = [0u8; 8];
    msg[..4].copy_from_slice(&step.to_ne_bytes());
    msg[4..].copy_from_slice(&err.to_ne_bytes());
    let _ = write_all(fd, &msg);
    sys::exit(127);
}

fn harness_main(p: &Plan, error_fd: RawFd) -> ! {
    let empty = sys::sig_empty_set();
    sys::sig_mask(libc::SIG_SETMASK, &empty);
    sys::reset_all_signals();
    #[cfg(feature = "test-build")]
    if knobs::no_isolation() {
        sys::set_pgroup_self();
    }
    // Decision 7 step 1: only 0-2 survive exec; the error pipe is fd 3
    // and close-on-exec.
    let mut error_fd = error_fd;
    if error_fd != 3 {
        if sys::dup3_cloexec(error_fd, 3).is_err() {
            let _ = fail(STEP_HARNESS_FD);
            harness_fail(error_fd);
        }
        error_fd = 3;
    }
    sys::close_from(4);
    let mut cwd = p.config.worktree_root.clone();
    if p.workdir.is_empty() {
        cwd = b"/tmp".to_vec();
    } else {
        cwd.push(b'/');
        cwd.extend_from_slice(&p.workdir);
    }
    if cwd.len() >= 4096 {
        let _ = fail_with(STEP_CWD_LENGTH, Errno::NAMETOOLONG);
        harness_fail(error_fd);
    }
    if drop_privileges(&p.op, true, STEP_HARNESS_DROP).is_err() {
        harness_fail(error_fd);
    }
    let Some(cwd_c) = sys::bytes_cstring(&cwd) else {
        let _ = fail_check(STEP_CHDIR);
        harness_fail(error_fd);
    };
    if let Err(e) = rustix::process::chdir(cwd_c.as_c_str()) {
        let _ = fail_with(STEP_CHDIR, e);
        harness_fail(error_fd);
    }
    let argv_ptrs: Vec<*const libc::c_char> = p
        .argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = p
        .envp
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let e = sys::execve(p.program.as_c_str(), &argv_ptrs, &envp_ptrs);
    let _ = fail_with(STEP_EXEC, e);
    harness_fail(error_fd);
}

/* ---- the init ---- */

extern "C" fn noop_handler(_sig: libc::c_int) {}

fn init_report(kind: u8, value: i32) {
    let mut msg = [0u8; 5];
    msg[0] = kind;
    msg[1..].copy_from_slice(&value.to_ne_bytes());
    let _ = write_all(3, &msg);
}

fn init_fail(fd: RawFd) -> ! {
    let (step, err) = failed();
    let mut msg = [0u8; 9];
    msg[0] = b'F';
    msg[1..5].copy_from_slice(&step.to_ne_bytes());
    msg[5..].copy_from_slice(&err.to_ne_bytes());
    let _ = write_all(fd, &msg);
    sys::exit(1);
}

fn init_main(p: &Plan, in_r: RawFd, out_w: RawFd, err_w: RawFd, status_w: RawFd) -> ! {
    // Move the four ends clear of 0-3 first, then into place. Until
    // then a failure is reported on the original status_w, which is
    // still open.
    let raw = [in_r, out_w, err_w, status_w];
    let mut fds = [-1i32; 4];
    for (i, r) in raw.iter().enumerate() {
        match sys::dupfd_cloexec(*r, 64) {
            Ok(d) => fds[i] = d.into_raw_fd(),
            Err(e) => {
                let _ = fail_with(STEP_INIT_FDS, e);
                init_fail(status_w);
            }
        }
    }
    if sys::dup2(fds[0], 0).is_err()
        || sys::dup2(fds[1], 1).is_err()
        || sys::dup2(fds[2], 2).is_err()
        || sys::dup3_cloexec(fds[3], 3).is_err()
    {
        let e = sys::last_errno();
        let _ = fail_with(STEP_INIT_FDS, e);
        init_fail(fds[3]);
    }
    for f in fds {
        sys::close(f);
    }
    sys::close_from(4);

    let mut set = sys::sig_empty_set();
    let sigs = [libc::SIGCHLD, libc::SIGTERM, libc::SIGINT, libc::SIGHUP];
    for s in sigs {
        sys::sig_add(&mut set, s);
        sys::sigaction_handler(s, noop_handler as *const () as usize);
    }
    sys::sig_mask(libc::SIG_BLOCK, &set);

    if !knobs::no_isolation() {
        if build_view(p).is_err() {
            init_fail(3); // build_view records its step
        }
    } else {
        sys::set_child_subreaper();
    }
    // The init's Landlock domain (decision 7) is created before the
    // harness is forked, so the harness's own domain (its drop) nests
    // inside it: the init's SIGTERM forwarding reaches the whole tree,
    // and nothing in the tree can signal the init or anything outside.
    // NO_NEW_PRIVS first, as the ruleset requires; the drop sets it
    // again.
    if let Err(e) = set_no_new_privs(true) {
        let _ = fail_with(STEP_INIT_NNP, e);
        init_fail(3);
    }
    if let Err(e) = landlock_scope() {
        let _ = fail_with(STEP_INIT_LANDLOCK, e);
        init_fail(3);
    }
    let (err_r, err_w_fd) = match pipe_with(PipeFlags::CLOEXEC) {
        Err(e) => {
            let _ = fail_with(STEP_ERROR_PIPE, e);
            init_fail(3);
        }
        Ok(pair) => pair,
    };
    let harness = match sys::fork() {
        Err(e) => {
            let _ = fail_with(STEP_HARNESS_FORK, e);
            init_fail(3);
        }
        Ok(sys::Fork::Parent(pid)) => pid.as_raw_nonzero().get(),
        Ok(sys::Fork::Child) => {
            drop(err_r);
            harness_main(p, err_w_fd.as_raw_fd());
        }
    };
    #[cfg(feature = "test-build")]
    if knobs::no_isolation() {
        sys::set_pgroup(harness);
    }
    drop(err_w_fd);
    // EOF with nothing read: the harness exec'd. Otherwise it failed at
    // the step it sent (a short or unreadable message is
    // harness_report).
    let mut child = [0u8; 8];
    let (got, read_errno) = match read_full(err_r.as_raw_fd(), &mut child) {
        Ok(g) => (g as i64, 0i32),
        Err(e) => (-1i64, e.raw_os_error()),
    };
    drop(err_r);
    let dropped = got == 0 && drop_privileges(&p.op, false, STEP_INIT_DROP).is_ok();
    if !dropped {
        let _ = sys::kill_pid(harness, libc::SIGKILL);
        while let Err(Errno::INTR) = waitpid(Some(sys::pid_from_raw(harness)), WaitOptions::empty())
        {
        }
        if got == 8 {
            let step = i32::from_ne_bytes(child[..4].try_into().unwrap_or_default());
            let err = i32::from_ne_bytes(child[4..].try_into().unwrap_or_default());
            let _ = fail_with(step, Errno::from_raw_os_error(err));
        } else if got != 0 {
            let _ = fail_check(STEP_HARNESS_REPORT);
            if got < 0 {
                let _ = fail_with(STEP_HARNESS_REPORT, Errno::from_raw_os_error(read_errno));
            }
        }
        init_fail(3);
    }
    init_report(b'R', harness);
    loop {
        let sig = sys::sig_wait(&set);
        if sig == libc::SIGTERM || sig == libc::SIGINT || sig == libc::SIGHUP {
            let forwarded = {
                #[cfg(feature = "test-build")]
                {
                    if knobs::no_isolation() {
                        let _ = sys::kill_pgroup(harness, libc::SIGTERM);
                        true
                    } else {
                        false
                    }
                }
                #[cfg(not(feature = "test-build"))]
                {
                    false
                }
            };
            if !forwarded {
                // Every process of this PID namespace but the init itself.
                let _ = sys::kill_all(libc::SIGTERM);
            }
            continue;
        }
        // SIGCHLD (or anything else): reap, report 'X' when the harness
        // ended.
        while let Ok(Some((pid, status))) = wait(WaitOptions::NOHANG) {
            if pid.as_raw_nonzero().get() == harness {
                init_report(b'X', status.as_raw());
                sys::exit(0);
            }
        }
    }
}

/* ---- the monitor ---- */

static MONITOR_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn monitor_stop_handler(_sig: libc::c_int) {
    MONITOR_STOP.store(true, Ordering::Relaxed);
}

struct Monitor<'a> {
    plan: &'a Plan,
    lifeline: RawFd,
    control: RawFd,
    status: RawFd,
    pidfd: RawFd,
    init_pid: i32,
    harness_pid: i32,
    launched: bool,
    lifeline_lost: bool,
    daemon_gone: bool,
    init_done: bool,
    have_hstatus: bool,
    killing: bool,
    forced: bool,
    released: bool,
    hstatus: i32,
    istatus: i32,
    kill_deadline: i64,
    forced_at: i64,
    pending: [RawFd; MAX_PENDING_KILLS],
    npending: usize,
}

impl<'a> Monitor<'a> {
    fn reap(&mut self) {
        while let Ok(Some((pid, status))) = wait(WaitOptions::NOHANG) {
            if pid.as_raw_nonzero().get() == self.init_pid {
                self.init_done = true;
                self.istatus = status.as_raw();
            }
        }
    }

    /// `has_processes` — the scope's liveness: the cgroup's populated
    /// flag, or, without isolation, the init and the harness's process
    /// group.
    fn has_processes(&mut self) -> bool {
        self.reap();
        if !self.init_done {
            return true;
        }
        #[cfg(feature = "test-build")]
        if knobs::no_isolation() {
            return self.harness_pid > 0 && sys::pgroup_alive(self.harness_pid);
        }
        crate::cgroup::scope_populated(&self.plan.scope).unwrap_or(true)
    }

    fn force_kill(&mut self) {
        if !self.init_done && self.pidfd >= 0 {
            let _ = sys::pidfd_send_signal(self.pidfd, libc::SIGKILL);
        }
        let _ = crate::cgroup::scope_kill(&self.plan.scope);
        #[cfg(feature = "test-build")]
        if knobs::no_isolation() && self.harness_pid > 0 {
            let _ = sys::kill_pgroup(self.harness_pid, libc::SIGKILL);
        }
        if !self.forced {
            self.forced_at = now_ms();
        }
        self.forced = true;
    }

    fn lose_lifeline(&mut self) {
        if self.lifeline_lost {
            return;
        }
        self.lifeline_lost = true;
        self.force_kill();
    }

    fn answer_pending(&mut self, status: Reason) {
        for fd in self.pending.iter().take(self.npending) {
            respond(*fd, Opcode::Kill, status, 0, 0);
            sys::close(*fd);
        }
        self.npending = 0;
    }

    fn start_kill(&mut self, grace_ms: u32) {
        if self.killing {
            return;
        }
        self.killing = true;
        self.kill_deadline = now_ms() + i64::from(grace_ms);
        if !self.init_done && self.pidfd >= 0 {
            let _ = sys::pidfd_send_signal(self.pidfd, libc::SIGTERM);
        }
    }

    fn handle_control(&mut self) {
        let mut msg = [0u8; 8];
        let (n, fd) = match recv_with_fd(self.control, &mut msg) {
            Err(Errno::AGAIN) => return,
            Err(_) => (-1i64, None),
            Ok((n, f)) => (n as i64, f),
        };
        if n <= 0 {
            self.daemon_gone = true;
            self.lose_lifeline();
            return;
        }
        match msg[0] {
            CTL_ALIVE => {
                if let Some(fd) = fd {
                    respond(
                        fd.as_raw_fd(),
                        Opcode::Alive,
                        Reason::Ok,
                        u8::from(self.has_processes()),
                        0,
                    );
                }
            }
            CTL_KILL => {
                let Some(fd) = fd else { return };
                if n < 5 {
                    return;
                }
                if !self.has_processes() {
                    respond(fd.as_raw_fd(), Opcode::Kill, Reason::Ok, 0, 0);
                } else if self.npending == MAX_PENDING_KILLS {
                    respond(fd.as_raw_fd(), Opcode::Kill, Reason::LaunchFailed, 0, 0);
                } else {
                    let grace = u32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
                    self.pending[self.npending] = fd.into_raw_fd();
                    self.npending += 1;
                    self.start_kill(grace);
                }
            }
            CTL_RELEASED => {
                self.released = true;
            }
            _ => {}
        }
    }

    fn read_status(&mut self) {
        let mut msg = [0u8; 5];
        let n = read_full(self.status, &mut msg[..1]);
        if n == Ok(1) && msg[0] == b'X' && read_full(self.status, &mut msg[1..]) == Ok(4) {
            self.hstatus = i32::from_ne_bytes(msg[1..].try_into().unwrap_or_default());
            self.have_hstatus = true;
            return;
        }
        sys::close(self.status);
        self.status = -1;
    }

    /// `wait_ready` waits for the init's 'R'. It returns false when
    /// setup failed, timed out, or the lifeline or the daemon went
    /// away first, with the failing step and errno recorded.
    fn wait_ready(&mut self) -> bool {
        let deadline = now_ms() + i64::from(knobs::setup_timeout_ms());
        let status_b = sys::borrow(self.status);
        let lifeline_b = sys::borrow(self.lifeline);
        loop {
            let mut pfd = [
                rustix::event::PollFd::new(&status_b, rustix::event::PollFlags::IN),
                rustix::event::PollFd::new(&lifeline_b, rustix::event::PollFlags::RDHUP),
            ];
            let left = deadline - now_ms();
            if left <= 0 {
                let _ = fail_with(STEP_SETUP_TIMEOUT, Errno::TIMEDOUT);
                return false;
            }
            if MONITOR_STOP.load(Ordering::Relaxed) {
                let _ = fail_with(STEP_SETUP_POLL, Errno::INTR);
                return false;
            }
            match rustix::event::poll(&mut pfd, Some(&ms_timespec(left))) {
                Err(Errno::INTR) => continue,
                Err(e) => {
                    let _ = fail_with(STEP_SETUP_POLL, e);
                    return false;
                }
                Ok(_) => {}
            }
            let r1 = pfd[1].revents();
            if r1.intersects(
                rustix::event::PollFlags::RDHUP
                    | rustix::event::PollFlags::HUP
                    | rustix::event::PollFlags::ERR,
            ) {
                self.lifeline_lost = true;
                let _ = fail_check(STEP_LIFELINE_LOST);
                return false;
            }
            if !pfd[0].revents().is_empty() {
                let mut msg = [0u8; 9];
                let n = read_full(self.status, &mut msg[..1]);
                if n == Ok(1) && msg[0] == b'F' && read_full(self.status, &mut msg[1..]) == Ok(8) {
                    let step = i32::from_ne_bytes(msg[1..5].try_into().unwrap_or_default());
                    let err = i32::from_ne_bytes(msg[5..9].try_into().unwrap_or_default());
                    let _ = fail_with(step, Errno::from_raw_os_error(err));
                    return false;
                }
                // EOF before any message: the init ended without
                // reporting (a signal, for example); the monitor logs
                // how it ended.
                if n != Ok(1) || msg[0] != b'R' || read_full(self.status, &mut msg[1..5]) != Ok(4) {
                    let _ = fail_check(STEP_STATUS_CHANNEL);
                    return false;
                }
                self.harness_pid = i32::from_ne_bytes(msg[1..5].try_into().unwrap_or_default());
                return true;
            }
        }
    }

    /// `service_control` waits up to `timeout_ms` for a control
    /// message and handles it, so forwarded ALIVE and KILL keep being
    /// answered while the monitor waits (the daemon never blocks on a
    /// monitor either way).
    fn service_control(&mut self, timeout_ms: i32) {
        if self.daemon_gone {
            sys::sleep_ms(timeout_ms);
            return;
        }
        let control_b = sys::borrow(self.control);
        let mut pfd = [rustix::event::PollFd::new(
            &control_b,
            rustix::event::PollFlags::IN,
        )];
        if matches!(
            rustix::event::poll(&mut pfd, Some(&ms_timespec(i64::from(timeout_ms)))),
            Ok(n) if n > 0
        ) {
            self.handle_control();
        }
    }

    /// `launch_failed` answers LAUNCH launch_failed (unless the
    /// lifeline is gone) and logs the failing step. An init that
    /// ended without reporting is waited for briefly so that its exit
    /// code is logged.
    fn launch_failed(&mut self) {
        if !self.lifeline_lost {
            respond(self.lifeline, Opcode::Launch, Reason::LaunchFailed, 0, 0);
        }
        let (step, err) = failed();
        log_step(
            "launch_failed",
            Reason::LaunchFailed,
            Some(&self.plan.scope),
            step,
            err,
        );
        if step != STEP_STATUS_CHANNEL || self.pidfd < 0 {
            return;
        }
        let pidfd_b = sys::borrow(self.pidfd);
        let mut pfd = [rustix::event::PollFd::new(
            &pidfd_b,
            rustix::event::PollFlags::IN,
        )];
        let _ = rustix::event::poll(&mut pfd, Some(&ms_timespec(1000)));
        self.reap();
        if !self.init_done {
            return;
        }
        let (code, _) = exit_code(self.istatus);
        log_init_ended(&self.plan.scope, code);
    }

    /// `finish` — wait for the init (bounded), drain the scope, release
    /// and answer EXIT when the session ended normally and ownership
    /// was released.
    fn finish(&mut self) -> ! {
        let scope = self.plan.scope;
        let init_deadline = (if self.forced {
            self.forced_at
        } else {
            now_ms()
        }) + i64::from(knobs::init_wait_timeout_ms());
        while !self.init_done {
            self.reap();
            if self.init_done {
                break;
            }
            if now_ms() >= init_deadline {
                self.force_kill();
                log("init_stuck", Reason::LaunchFailed, Some(&scope));
                break;
            }
            self.service_control(10);
        }
        if self.status >= 0 {
            let _ = sys::set_nonblock(self.status);
            self.read_status();
        }
        if self.has_processes() {
            self.force_kill();
        }
        let deadline = now_ms() + i64::from(knobs::drain_timeout_ms());
        let mut drained = !self.has_processes();
        while !drained && now_ms() < deadline {
            self.service_control(10);
            drained = !self.has_processes();
        }
        #[cfg(feature = "test-build")]
        if drained && knobs::no_isolation() {
            crate::cgroup::scope_mark(&scope, false);
        }
        self.answer_pending(if drained {
            Reason::Ok
        } else {
            Reason::LaunchFailed
        });
        if drained && crate::cgroup::scope_remove(&scope).is_err() {
            drained = false;
        }
        // Release: the daemon drops ownership and acknowledges.
        // Forwarded requests that arrive meanwhile see an empty scope.
        if !self.daemon_gone {
            let msg = [CTL_RELEASE];
            if send_fds(self.control, &msg, &[]).is_err() {
                self.daemon_gone = true;
            }
            let until = now_ms() + i64::from(knobs::drain_timeout_ms());
            while !self.released && !self.daemon_gone && now_ms() < until {
                let control_b = sys::borrow(self.control);
                let mut pfd = [rustix::event::PollFd::new(
                    &control_b,
                    rustix::event::PollFlags::IN,
                )];
                if matches!(
                    rustix::event::poll(&mut pfd, Some(&ms_timespec(100))),
                    Ok(n) if n > 0
                ) {
                    self.handle_control();
                }
            }
        }
        if self.launched && !self.lifeline_lost && drained && self.released {
            let (code, signaled) = exit_code(if self.have_hstatus {
                self.hstatus
            } else {
                self.istatus
            });
            respond(
                self.lifeline,
                Opcode::Exit,
                Reason::Ok,
                u8::from(signaled),
                code as u16,
            );
            log("session_exited", Reason::Ok, Some(&scope));
        } else {
            log(
                "session_ended",
                if drained {
                    Reason::Ok
                } else {
                    Reason::LaunchFailed
                },
                Some(&scope),
            );
        }
        sys::exit(0);
    }
}

/// `exit_code` — the wire's exit code and signaled bit from a raw wait
/// status.
fn exit_code(status: i32) -> (i32, bool) {
    if libc::WIFEXITED(status) {
        return (libc::WEXITSTATUS(status), false);
    }
    if libc::WIFSIGNALED(status) {
        return (128 + libc::WTERMSIG(status), true);
    }
    (255, false)
}

/// `chl_monitor_main` — runs a launch's monitor in a freshly forked
/// child; never returns. `lifeline` is the LAUNCH connection; `control`
/// the monitor's end of the control socketpair.
pub fn monitor_main(lifeline: RawFd, control: RawFd, plan: &Plan) -> ! {
    // Only the lifeline (3) and the control socket (4) are kept.
    let raw = [lifeline, control];
    let mut keep = [-1i32; 2];
    for (i, fd) in raw.iter().enumerate() {
        match sys::dupfd_cloexec(*fd, 64) {
            Ok(d) => keep[i] = d.into_raw_fd(),
            Err(e) => {
                log_step(
                    "launch_failed",
                    Reason::LaunchFailed,
                    Some(&plan.scope),
                    STEP_MONITOR_FDS,
                    e.raw_os_error(),
                );
                sys::exit(1);
            }
        }
    }
    if sys::dup3_cloexec(keep[0], 3).is_err() || sys::dup3_cloexec(keep[1], 4).is_err() {
        log_step(
            "launch_failed",
            Reason::LaunchFailed,
            Some(&plan.scope),
            STEP_MONITOR_FDS,
            sys::last_errno().raw_os_error(),
        );
        sys::exit(1);
    }
    // cgroup.rs keeps its scopes directory open; re-open it past 5 below.
    sys::close_from(5);
    if let Err(e) = crate::cgroup::reopen() {
        log_step(
            "launch_failed",
            Reason::LaunchFailed,
            Some(&plan.scope),
            STEP_CGROUP_REOPEN,
            e.raw_os_error(),
        );
        sys::exit(1);
    }

    sys::sigaction_handler(libc::SIGTERM, monitor_stop_handler as *const () as usize);
    sys::sigaction_handler(libc::SIGINT, monitor_stop_handler as *const () as usize);
    sys::set_child_subreaper();

    let mut m = Monitor {
        plan,
        lifeline: 3,
        control: 4,
        status: -1,
        pidfd: -1,
        init_pid: 0,
        harness_pid: 0,
        launched: false,
        lifeline_lost: false,
        daemon_gone: false,
        init_done: false,
        have_hstatus: false,
        killing: false,
        forced: false,
        released: false,
        hstatus: 0,
        istatus: 0,
        kill_deadline: 0,
        forced_at: 0,
        pending: [-1; MAX_PENDING_KILLS],
        npending: 0,
    };

    let mut pipes: [Option<(OwnedFd, OwnedFd)>; 4] = [None, None, None, None];
    let mut pipes_ok = true;
    for slot in pipes.iter_mut() {
        match pipe_with(PipeFlags::CLOEXEC) {
            Ok(p) => *slot = Some(p),
            Err(e) => {
                let _ = fail_with(STEP_MONITOR_PIPE, e);
                pipes_ok = false;
                break;
            }
        }
    }
    if !pipes_ok {
        m.init_done = true;
        m.launch_failed();
        m.finish();
    }
    let take = |s: Option<(OwnedFd, OwnedFd)>| -> (RawFd, RawFd) {
        match s {
            Some((r, w)) => (r.into_raw_fd(), w.into_raw_fd()),
            None => (-1, -1),
        }
    };
    let (in_r, in_w) = take(pipes[0].take());
    let (out_r, out_w) = take(pipes[1].take());
    let (err_r, err_w) = take(pipes[2].take());
    let (status_r, status_w) = take(pipes[3].take());

    let mut args = libc::clone_args {
        flags: 0,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: 0,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    args.flags = libc::CLONE_PIDFD as u64;
    let mut pidfd: RawFd = -1;
    args.pidfd = &mut pidfd as *mut RawFd as u64;
    args.exit_signal = libc::SIGCHLD as u64;
    let mut cgroup: Option<OwnedFd> = None;
    if !knobs::no_isolation() {
        match crate::cgroup::scope_open(&plan.scope) {
            Err(e) => {
                let _ = fail_with(STEP_SCOPE_OPEN, e);
                m.init_done = true;
                m.launch_failed();
                m.finish();
            }
            Ok(c) => {
                // CLONE_INTO_CGROUP (libc's const is deprecated for a
                // type width it will outgrow; the flag value is fixed
                // in the ABI).
                args.flags |= (libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWIPC) as u64
                    | 0x2000_0000;
                args.cgroup = c.as_raw_fd() as u64;
                cgroup = Some(c);
            }
        }
    } else {
        #[cfg(feature = "test-build")]
        crate::cgroup::scope_mark(&plan.scope, true);
    }
    match sys::clone3(&args) {
        Err(e) => {
            let _ = fail_with(STEP_CLONE3, e);
            m.init_done = true;
            m.launch_failed();
            m.finish();
        }
        Ok(0) => {
            sys::close(in_w);
            sys::close(out_r);
            sys::close(err_r);
            sys::close(status_r);
            init_main(plan, in_r, out_w, err_w, status_w);
        }
        Ok(pid) => {
            drop(cgroup);
            sys::close(in_r);
            sys::close(out_w);
            sys::close(err_w);
            sys::close(status_w);
            m.status = status_r;
            m.pidfd = pidfd;
            m.init_pid = pid;
        }
    }
    if !m.wait_ready() {
        m.launch_failed();
        m.force_kill();
        m.finish();
    }
    let frame = wire::encode_response(&wire::Response {
        op: Opcode::Launch,
        status: Reason::Ok,
        ..wire::Response::default()
    });
    let handoff = [in_w, out_r, err_r, m.pidfd];
    match frame {
        Ok(f) if send_fds(m.lifeline, &f, &handoff).is_ok() => {}
        _ => m.lose_lifeline(),
    }
    sys::close(in_w);
    sys::close(out_r);
    sys::close(err_r);
    m.launched = true;
    log("session_started", Reason::Ok, Some(&plan.scope));

    while !m.init_done {
        if MONITOR_STOP.load(Ordering::Relaxed) {
            m.lose_lifeline();
        }
        // An init that does not end after its SIGKILL: finish() bounds
        // the rest.
        if m.forced && now_ms() - m.forced_at >= i64::from(knobs::init_wait_timeout_ms()) {
            break;
        }
        if m.killing && !m.forced && now_ms() >= m.kill_deadline && m.has_processes() {
            m.force_kill();
        }
        if m.npending > 0 && !m.has_processes() {
            m.answer_pending(Reason::Ok);
        }
        if m.init_done {
            break;
        }
        let mut borrows: Vec<BorrowedFd> = Vec::with_capacity(4);
        let mut tags: Vec<u8> = Vec::with_capacity(4);
        let mut events: Vec<rustix::event::PollFlags> = Vec::with_capacity(4);
        if m.status >= 0 {
            borrows.push(sys::borrow(m.status));
            tags.push(0);
            events.push(rustix::event::PollFlags::IN);
        }
        if !m.lifeline_lost {
            borrows.push(sys::borrow(m.lifeline));
            tags.push(1);
            events.push(rustix::event::PollFlags::IN | rustix::event::PollFlags::RDHUP);
        }
        if !m.daemon_gone {
            borrows.push(sys::borrow(m.control));
            tags.push(2);
            events.push(rustix::event::PollFlags::IN);
        }
        borrows.push(sys::borrow(m.pidfd));
        tags.push(3);
        events.push(rustix::event::PollFlags::IN);
        let mut pfds: Vec<rustix::event::PollFd> = borrows
            .iter()
            .zip(events.iter())
            .map(|(b, e)| rustix::event::PollFd::new(b, *e))
            .collect();
        let ready = rustix::event::poll(&mut pfds, Some(&ms_timespec(50)));
        if !matches!(ready, Ok(n) if n > 0) {
            continue;
        }
        for (i, tag) in tags.iter().enumerate() {
            if pfds[i].revents().is_empty() {
                continue;
            }
            match tag {
                0 => m.read_status(),
                1 => m.lose_lifeline(),
                2 => m.handle_control(),
                _ => {}
            }
        }
        m.reap();
    }
    m.finish();
}

/// `socketpair(AF_UNIX, SOCK_SEQPACKET|SOCK_CLOEXEC)` — the
/// daemon<->monitor control channel (main.rs).
pub fn control_pair() -> Result<(OwnedFd, OwnedFd), Errno> {
    socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
}
