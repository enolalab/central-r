//! The broker's default-deny seccomp-BPF filter — a byte-for-byte port
//! of upstream `internal/adapter/authority/broker/hardening.go`'s
//! `installSeccompFilter`.
//!
//! The program shape (and the trap that made every historic filter
//! kill its own process):
//!
//! 1. `LD seccomp_data.arch` — offset 4.
//! 2. `JEQ AUDIT_ARCH_X86_64` with `jt=1, jf=0` — a match *skips* the
//!    following `KILL`; the upstream SC-DEF-02 note records that the
//!    inverted pair (`jt=0, jf=1`) made the filter kill every process
//!    on its first syscall regardless of the allow-list, and no test
//!    ever saw the filter allow anything before the fix.
//! 3. `RET KILL_PROCESS` for every non-x86-64 arch.
//! 4. `LD seccomp_data.nr` — offset 0.
//! 5. A linear scan: `JEQ nr → RET ALLOW` per [`ALLOWED_SYSCALLS`]
//!    entry, in upstream's order.
//! 6. `RET KILL_PROCESS` — the default.
//!
//! Install goes through `sys::audited::install_filter` — the `seccomp(2)`
//! `SECCOMP_SET_MODE_FILTER|TSYNC` call is the one raw syscall rustix
//! 1.1 has no safe API for (R5 decision D2). The caller sets
//! `no_new_privs` first (upstream's probe does `PR_SET_NO_NEW_PRIVS`
//! then `installSeccompFilter`; an unprivileged install is refused by
//! the kernel otherwise), and a failed install must fail closed — the
//! broker refuses to start unhardened.
//!
//! ## Rust syscall surface (R5 T9 P0-A, ADR 0044)
//!
//! The upstream 64-number allow-list was written against Go's runtime
//! emission table. Rust's stdlib reaches a *different* set for the same
//! calls, so a verbatim port died with `SIGSYS` on its first hardened
//! store operation: `std::fs::metadata`/`symlink_metadata`/`Path::exists`
//! emit `statx` (332 — not listed; `newfstatat` 262 is),
//! `std::fs::set_permissions` emits `fchmodat` (268 — not listed;
//! `fchmod` 91 is), `UnixStream::set_read/write_timeout` emits
//! `setsockopt` (54 — not listed), `UnixListener::set_nonblocking` and
//! `UnixStream::set_nonblocking` emit `ioctl(FIONBIO)` (16 — not
//! listed), and tokio's `signal` needs `socketpair`+`poll` (53/7 —
//! not listed). Rather than widening the list to fit the naive port,
//! the port was re-aimed at primitives already on it (ADR 0044):
//! `rustix::fs::statat`/`newfstatat` for metadata, `openat` mode bits
//! and fd `fchmod`/`fchown` for permissions/ownership, `mkdirat`/
//! `unlinkat`/`linkat`/`renameat2`/`getdents64` for the store tree,
//! `fcntl(O_NONBLOCK)` + `read`/`write`/`recvmsg` `EAGAIN` retry under
//! a `nanosleep` deadline for the connection layer, and `rt_sigaction`
//! flag handlers for signal shutdown. Round 2 (the P0-A migration was
//! incomplete) removed the residual `std::fs` path calls `std` emitted
//! as `rename` (82 — unconditional on x86_64), `unlink` (87), `link`
//! (86), and `fchownat` (260) — every rename now goes through
//! `durable::rename_replace`/`rename_noreplace` (`renameat2` 316),
//! removals through `durable::remove_file`/`remove_all` (`unlinkat`
//! 263), the signing publish through `durable::hard_link` (`linkat`
//! 265), and the export-identity `chown` through `fchown` (93) on the
//! open fd. The list itself is unchanged — the `broker_surface` probe
//! walks every post-`harden()` emission and the `old_shape` probes pin
//! `fchmodat`/`statx`/`rename`/`unlink`/`link`/`fchownat` to `SIGSYS`.

use central_foundation::failure::Failure;

use crate::sys::audited;

/// `AUDIT_ARCH_X86_64` (`EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE`)
/// — upstream's `0xC000003E` literal.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `seccomp_data.nr` — BPF load offset of the syscall number.
const OFF_NR: u32 = 0;
/// `seccomp_data.arch` — BPF load offset of the audit arch.
const OFF_ARCH: u32 = 4;

/// The x86-64 allow-list — `hardening.go`'s `allowed`, verbatim and in
/// order (the kernel sees a linear scan; order is load-bearing only for
/// audit-diff review). Every comment block in upstream maps to a
/// contiguous group below; the numbers are what the filter contains.
pub const ALLOWED_SYSCALLS: &[u32] = &[
    // The original list: read, write, close, mmap, mprotect, brk,
    // rt_sigaction, rt_sigreturn, writev, sched_yield, nanosleep,
    // getpid, accept, getsockopt, exit, fstat, flock, fsync, fchmod,
    // geteuid, fcntl, futex, clock_gettime, exit_group, epoll_wait,
    // epoll_ctl, openat, newfstatat, mkdirat, unlinkat, renameat,
    // linkat, prctl, epoll_create1, fstatfs, renameat2, getrandom,
    // memfd_create, eventfd2, epoll_pwait, tgkill, openat2, sendmsg,
    // recvmsg — as documented above `allowed` in the Go source.
    0, 1, 3, 9, 10, 12, 13, 15, 20, 24, 35, 39, 43, 55, 60, 72, 202, 228, 231, 232, 233, 257, 262,
    291, 316, 318, 319,
    // SC-DEF-07 — the daemon's serving path, enumerated by strace of a
    // filter-neutralised daemon through startup and Serve.
    51,  // getsockname
    52,  // getpeername
    214, // epoll_ctl
    288, // accept4
    // SC-DEF-02 — the dispatch surface: journal flocks, protected-file
    // chmod, owner validation, B10 tmpfs validation, link-at bootstrap.
    5,   // fstat
    73,  // flock
    74,  // fsync
    91,  // fchmod
    107, // geteuid
    138, // fstatfs
    265, // linkat
    258, // mkdirat
    263, // unlinkat
    264, // renameat
    157, // prctl (Go's runtime.setVMAName / PR_SET_VMA)
    290, // eventfd2 (the runtime netpoller's lazy init)
    281, // epoll_pwait (the netpoller's real wait on this toolchain)
    234, // tgkill (SIGURG async preemption)
    437, // openat2 (protected_file generation reads)
    // SCM_RIGHTS descriptor handoff — net.UnixConn's WriteMsgUnix /
    // ReadMsgUnix (the B04/B05/B10 delivery paths).
    46, // sendmsg
    47, // recvmsg
    // SC-DEF-10 — real lifecycle execution.
    204, // sched_getaffinity
    // SC-DEF-24 — lazy thread creation family (newosproc/minit and the
    // cgo pthread_create → clone3 path) plus madvise/munmap stack work.
    14,  // rt_sigprocmask
    56,  // clone
    435, // clone3
    131, // sigaltstack
    186, // gettid
    273, // set_robust_list
    334, // rseq
    28,  // madvise
    11,  // munmap
    17,  // pread64 (runtime's periodic cgroup cpu.max re-read)
    // ADR 0029 — os.ReadDir throughout the daemon's own stores.
    217, // getdents64
    // SC-DEF-36 — verifyPeerProcess's /proc/<pid>/exe EvalSymlinks.
    267, // readlinkat
    // SC-DEF-40 — Handoff's memfd rewind before F_ADD_SEALS.
    8, // lseek
    // SC-DEF-45 — the throughput-probe credential fchown.
    93, // fchown
    // SC-DEF-48 — the kernel re-driving a SIGURG-interrupted slow
    // syscall; not issued by any call site directly.
    219, // restart_syscall
];

const BPF_LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const BPF_JMP_JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
const BPF_RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;

const fn ld(k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt,
        jf,
        k,
    }
}

const fn ret(k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Build the `sock_filter` program — `installSeccompFilter`'s
/// `filter` slice, instruction for instruction. `pub(crate)` so the
/// shape test pins the layout and `install` passes it to the audited
/// boundary.
pub(crate) fn program() -> Vec<libc::sock_filter> {
    let mut filter = Vec::with_capacity(4 + ALLOWED_SYSCALLS.len() * 2 + 1);
    // arch check — the SC-DEF-02 direction: JEQ's `jt=1` skips the
    // KILL on a match, `jf=0` falls through into it otherwise.
    filter.push(ld(OFF_ARCH));
    filter.push(jeq(AUDIT_ARCH_X86_64, 1, 0));
    filter.push(ret(RET_KILL_PROCESS));
    // syscall-number linear scan.
    filter.push(ld(OFF_NR));
    for &nr in ALLOWED_SYSCALLS {
        filter.push(jeq(nr, 0, 1));
        filter.push(ret(RET_ALLOW));
    }
    filter.push(ret(RET_KILL_PROCESS));
    filter
}

/// `installSeccompFilter` — install [`program`] on every thread of
/// this process (`SECCOMP_FILTER_FLAG_TSYNC`, upstream's flag and the
/// only honest install for a daemon).
///
/// The caller must set `no_new_privs` first (or hold `CAP_SYS_ADMIN`) —
/// upstream's probe does `PR_SET_NO_NEW_PRIVS` then this call.
///
/// # Errors
/// `sys_seccomp_denied` when the kernel refuses the install
/// (`EACCES`/`EPERM` without `no_new_privs`); `sys_seccomp_invalid`
/// when the program cannot be described (`len` overflow); any failure
/// must abort startup — a broker without its filter is not a broker.
pub fn install() -> Result<(), Failure> {
    let mut filter = program();
    let len = u16::try_from(filter.len()).map_err(|_| {
        Failure::invalid(
            "sys_seccomp_invalid",
            format!("filter program length {} exceeds u16", filter.len()),
        )
    })?;
    let prog = libc::sock_fprog {
        len,
        filter: filter.as_mut_ptr(),
    };
    audited::install_filter(&prog)
        .map_err(|e| Failure::denied("sys_seccomp_denied", format!("seccomp install failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    /// The allow-list pins upstream `hardening.go`'s `allowed` — the
    /// exact 64 numbers, in order, including every SC-DEF addition and
    /// the documented exclusions' presence/absence:
    /// `getdents64` IS admitted (ADR 0029), `fallocate` is NOT.
    #[test]
    fn allowlist_matches_upstream() {
        const UPSTREAM: &[u32] = &[
            0, 1, 3, 9, 10, 12, 13, 15, 20, 24, 35, 39, 43, 55, 60, 72, 202, 228, 231, 232, 233,
            257, 262, 291, 316, 318, 319, 51, 52, 214, 288, 5, 73, 74, 91, 107, 138, 265, 258, 263,
            264, 157, 290, 281, 234, 437, 46, 47, 204, 14, 56, 435, 131, 186, 273, 334, 28, 11, 17,
            217, 267, 8, 93, 219,
        ];
        assert_eq!(ALLOWED_SYSCALLS, UPSTREAM);
        assert_eq!(ALLOWED_SYSCALLS.len(), 64);
        // Load-bearing absences/presences upstream names explicitly.
        assert!(!ALLOWED_SYSCALLS.contains(&285), "fallocate must stay out");
        assert!(
            ALLOWED_SYSCALLS.contains(&217),
            "getdents64 admitted by ADR 0029"
        );
        assert!(ALLOWED_SYSCALLS.contains(&46)); // sendmsg
        assert!(ALLOWED_SYSCALLS.contains(&47)); // recvmsg
        assert!(ALLOWED_SYSCALLS.contains(&219)); // restart_syscall
        // No duplicates.
        let mut sorted = ALLOWED_SYSCALLS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALLOWED_SYSCALLS.len());
    }

    /// The program is exactly upstream's shape: arch load, arch JEQ
    /// with the SC-DEF-02 direction (jt=1/jf=0 — match *skips* the
    /// kill), KILL, nr load, a JEQ→ALLOW pair per allow-list entry,
    /// terminal KILL.
    #[test]
    fn program_shape_matches_upstream() {
        let p = program();
        assert_eq!(p.len(), 4 + ALLOWED_SYSCALLS.len() * 2 + 1);

        // [0] LD arch
        assert_eq!(
            (p[0].code, p[0].jt, p[0].jf, p[0].k),
            (BPF_LD_W_ABS, 0, 0, OFF_ARCH)
        );
        // [1] JEQ x86_64 → skip [2]
        assert_eq!(
            (p[1].code, p[1].jt, p[1].jf, p[1].k),
            (BPF_JMP_JEQ_K, 1, 0, AUDIT_ARCH_X86_64)
        );
        // [2] KILL non-x86-64
        assert_eq!((p[2].code, p[2].k), (BPF_RET_K, RET_KILL_PROCESS));
        // [3] LD nr
        assert_eq!((p[3].code, p[3].k), (BPF_LD_W_ABS, OFF_NR));
        // JEQ → ALLOW pairs, upstream order.
        for (i, &nr) in ALLOWED_SYSCALLS.iter().enumerate() {
            let j = &p[4 + i * 2];
            let a = &p[5 + i * 2];
            assert_eq!(
                (j.code, j.jt, j.jf, j.k),
                (BPF_JMP_JEQ_K, 0, 1, nr),
                "jeq[{i}]"
            );
            assert_eq!((a.code, a.k), (BPF_RET_K, RET_ALLOW), "allow[{i}]");
        }
        // Terminal KILL — the default.
        let last = p.last().expect("nonempty");
        assert_eq!((last.code, last.k), (BPF_RET_K, RET_KILL_PROCESS));
    }

    /// Probe child: set `no_new_privs`, install the real filter, then
    /// issue an allowed syscall (`getpid`) and exit 0 — the upstream
    /// `runSeccompProbe` shape. Parent asserts clean exit.
    #[test]
    fn probe_child_allows_listed_syscall() {
        if !crate::sys::probe::is("allow") {
            return;
        }
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // 39 = getpid is on the list; issuing it under the filter is
        // the whole proof.
        assert_eq!(
            rustix::process::getpid().as_raw_pid(),
            std::process::id() as i32
        );
        std::process::exit(0);
    }

    /// Probe child: same install, then issue `getcwd` (79) — not on
    /// the list — expecting death by `SIGSYS`, upstream's
    /// `runProbeExpectingSIGSYS`.
    #[test]
    fn probe_child_denied_syscall_dies() {
        if !crate::sys::probe::is("deny") {
            return;
        }
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // 79 = getcwd is NOT on the allow-list; the kernel kills this
        // process with SIGSYS here — we never reach the exit.
        let _ = std::env::current_dir();
        std::process::exit(42);
    }

    /// Parent halves — clean exit for the allowed probe, `SIGSYS` for
    /// the denied one.
    #[test]
    fn filter_allows_and_kills() {
        let allow = crate::sys::probe::run_on(
            "sys::seccomp::tests::probe_child_allows_listed_syscall",
            "allow",
        );
        assert!(allow.success(), "allowed-syscall probe died: {allow:?}");

        let deny = crate::sys::probe::run_on(
            "sys::seccomp::tests::probe_child_denied_syscall_dies",
            "deny",
        );
        assert_eq!(
            deny.signal(),
            Some(libc::SIGSYS),
            "denied-syscall probe must die by SIGSYS, got {deny:?}"
        );
    }

    /// An install without `no_new_privs` under a non-root caller is
    /// refused — `EPERM`/`EACCES`, upstream's `TestSeccompFilterRunsUnprivileged`
    /// premise (the kernel's precondition, fail-closed).
    #[test]
    fn install_without_nnp_fails_closed_unpriv() {
        if rustix::process::geteuid().is_root() {
            return; // root is permitted without nnp — nothing to assert
        }
        let err = install().unwrap_err();
        assert_eq!(err.code(), "sys_seccomp_denied");
    }

    /// Probe child: install the filter, then walk the hardened
    /// broker's real post-`harden()` syscall surface — the durable
    /// store (`newfstatat`/`mkdirat`/`openat`/`getdents64`/`unlinkat`/
    /// `renameat2`/`fchmod`/`fsync`), the connection layer (`fcntl`
    /// `O_NONBLOCK`, `read`/`write`, `sendmsg`/`recvmsg`,
    /// `getsockopt`, `accept4`), the signal shutdown (`rt_sigaction`),
    /// and the cadence/runtime calls (`nanosleep`, `clock_gettime`,
    /// `getrandom`, `getpid`/`geteuid`). A single missed emission is a
    /// `SIGSYS` death — the P0-A regression this proves stays out.
    /// R5 T9 / ADR 0044.
    #[test]
    fn probe_child_broker_surface() {
        if !crate::sys::probe::is("broker-surface") {
            return;
        }
        use std::os::fd::AsFd as _;
        use std::os::unix::net::UnixListener;

        // Pre-install fixtures: socketpair/listener need `socketpair`
        // and `bind`/`listen`, none of which the filter admits — the
        // daemon creates its socket before `harden()` for the same
        // reason.
        let (a, b) = std::os::unix::net::UnixStream::pair().expect("socketpair fixture");
        let dir = std::env::temp_dir().join(format!("central-surf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("fixture dir");
        let sock_path = dir.join("l.sock");
        let listener = UnixListener::bind(&sock_path).expect("fixture listener");

        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");

        // -- durable-store surface (broker/durable.rs primitives) --
        let store = dir.join("store");
        crate::broker::durable::mkdir_p(&store, 0o700).expect("mkdir_p");
        let f = store.join("k.json");
        crate::broker::durable::write_file(&f, b"{}", 0o600).expect("write_file");
        let st = crate::broker::durable::stat(&f).expect("stat");
        assert!(rustix::fs::FileType::from_raw_mode(st.st_mode).is_file());
        let lst = crate::broker::durable::lstat(&f).expect("lstat");
        assert_eq!(st.st_ino, lst.st_ino);
        assert!(crate::broker::durable::exists(&f));
        assert_eq!(
            crate::broker::durable::read_dir(&store)
                .expect("read_dir")
                .len(),
            1
        );
        crate::broker::durable::sync_file(&f).expect("sync_file");
        crate::broker::durable::sync_dir(&store).expect("sync_dir");
        // fchmod(91) — the fd-based permission path write_private uses.
        let fd = rustix::fs::openat(
            rustix::fs::CWD,
            &f,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("openat");
        rustix::fs::fchmod(&fd, rustix::fs::Mode::from_raw_mode(0o600)).expect("fchmod");
        let tmp = store.join("k.tmp");
        crate::broker::durable::write_file(&tmp, b"{}", 0o600).expect("tmp write");
        crate::broker::durable::rename_replace(&tmp, &f).expect("renameat2");
        // The persist shape that leaked before the round-2 fix:
        // tmp-write -> fsync -> atomic replace, the `unlinkat`
        // rollback/cleanup, the `linkat` publish, and the
        // `RENAME_NOREPLACE` journal commit (N1/N2 sites).
        crate::broker::durable::replace_json(&store.join("j.json"), &serde_json::json!({"k": 1}))
            .expect("replace_json");
        let link = store.join("j.link");
        crate::broker::durable::hard_link(&store.join("j.json"), &link).expect("linkat");
        crate::broker::durable::remove_file(&link).expect("unlinkat");
        let occupied = store.join("occupied.json");
        crate::broker::durable::write_file(&occupied, b"{}", 0o600).expect("occupied target");
        let tmp2 = store.join("k2.tmp");
        crate::broker::durable::write_file(&tmp2, b"{}", 0o600).expect("tmp2 write");
        assert!(
            crate::broker::durable::rename_noreplace(&tmp2, &occupied).is_err(),
            "rename_noreplace must refuse an occupied target"
        );
        crate::broker::durable::remove_file(&tmp2).expect("tmp2 unlink");
        crate::broker::durable::remove_all(&store).expect("remove_all");

        // -- connection surface (broker/deadline.rs + scm_rights) --
        let flags = rustix::fs::fcntl_getfl(&b).expect("fcntl_getfl");
        rustix::fs::fcntl_setfl(&b, flags | rustix::fs::OFlags::NONBLOCK).expect("fcntl_setfl");
        rustix::io::write(&a, b"x").expect("write socket");
        let mut data = [0u8; 4];
        let recv = crate::sys::scm_rights::recv_raw(&b, &mut data).expect("recvmsg");
        drop(recv);
        crate::sys::scm_rights::send(&a, &[0x01], &[fd.as_fd()]).expect("sendmsg");
        crate::sys::peercred::peercred(&a).expect("getsockopt SO_PEERCRED");
        // accept4(288): nonblocking listener accept -> EAGAIN.
        let lflags = rustix::fs::fcntl_getfl(&listener).expect("listener getfl");
        rustix::fs::fcntl_setfl(&listener, lflags | rustix::fs::OFlags::NONBLOCK)
            .expect("listener nonblock");
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            // Any non-EAGAIN outcome fails the probe deterministically.
            _ => std::process::exit(43),
        }

        // -- signal surface (daemon shutdown flag handlers) --
        extern "C" fn noop(_sig: libc::c_int) {}
        audited::install_signal_handler(libc::SIGUSR1, noop).expect("rt_sigaction");

        // -- cadence/runtime surface --
        audited::nanosleep(std::time::Duration::from_millis(1)); // nanosleep(35)
        let _ = std::time::Instant::now(); // clock_gettime
        let mut entropy = [0u8; 8];
        rustix::rand::getrandom(&mut entropy[..], rustix::rand::GetRandomFlags::empty())
            .expect("getrandom");
        let _ = rustix::process::getpid();
        let _ = rustix::process::geteuid();

        std::process::exit(0);
    }

    /// Probe child: the pre-fix permission path — `std::fs`'s
    /// `set_permissions` emits `fchmodat` (268), absent from the
    /// allow-list by design (fd `fchmod` is what the fixed port uses).
    /// The kernel kills this child with `SIGSYS`; reaching `exit(42)`
    /// would mean the regression's old shape silently passes.
    #[test]
    fn probe_child_old_fchmodat_dies() {
        if !crate::sys::probe::is("old-fchmodat") {
            return;
        }
        let f = std::env::temp_dir().join(format!("central-oldf-{}", std::process::id()));
        std::fs::write(&f, b"x").expect("fixture file");
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // fchmodat(268) — SIGSYS here; never returns.
        let _ = std::fs::set_permissions(
            &f,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        );
        std::process::exit(42);
    }

    /// Probe child: the pre-fix metadata path — `statx` (332) is what
    /// `std::fs::metadata`/`symlink_metadata`/`Path::exists` emit on a
    /// modern toolchain, and it is not on the allow-list
    /// (`newfstatat` is the listed primitive the port switched to).
    /// The raw `statx` call pins the regression deterministically,
    /// independent of which emission std picks on a given rustc.
    #[test]
    fn probe_child_old_statx_dies() {
        if !crate::sys::probe::is("old-statx") {
            return;
        }
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // Raw `statx` via the audited boundary — this module is
        // `#[forbid(unsafe_code)]`; the filter kills here and the
        // call never returns.
        let _ = audited::statx_raw(c"/");
        std::process::exit(42);
    }

    /// Probe child: the pre-fix rename emission — `fs::rename` reaches
    /// `rename` (82) unconditionally on x86_64; the allow-list carries
    /// `renameat` (264)/`renameat2` (316) only. The raw syscall pins
    /// the regression deterministically regardless of what std picks
    /// on a given toolchain (R5 T9 P0-A round 2).
    #[test]
    fn probe_child_old_rename_dies() {
        if !crate::sys::probe::is("old-rename") {
            return;
        }
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // rename(82) — the filter kills on entry; never returns.
        let _ = audited::rename_raw(c"/nonexistent-a", c"/nonexistent-b");
        std::process::exit(42);
    }

    /// Probe child: the pre-fix remove emission — `fs::remove_file`
    /// reaches `unlink` (87) on glibc ≥ 2.37 (and only `unlinkat` on
    /// older toolchains); the raw syscall pins the denied primitive,
    /// toolchain-independent (R5 T9 P0-A round 2).
    #[test]
    fn probe_child_old_unlink_dies() {
        if !crate::sys::probe::is("old-unlink") {
            return;
        }
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // unlink(87) — the filter kills on entry; never returns.
        let _ = audited::unlink_raw(c"/nonexistent");
        std::process::exit(42);
    }

    /// Probe child: the pre-fix hard-link emission — `fs::hard_link`
    /// reaches `link` (86) on glibc ≥ 2.37; the raw syscall pins the
    /// denied primitive (R5 T9 P0-A round 2).
    #[test]
    fn probe_child_old_link_dies() {
        if !crate::sys::probe::is("old-link") {
            return;
        }
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // link(86) — the filter kills on entry; never returns.
        let _ = audited::link_raw(c"/nonexistent-a", c"/nonexistent-b");
        std::process::exit(42);
    }

    /// Probe child: the pre-fix ownership emission — the path-based
    /// `rustix::fs::chown` the export-identity mint used reaches
    /// `fchownat` (260); the allow-listed shape is `fchown` (93) on
    /// the open fd (R5 T9 P0-A round 2).
    #[test]
    fn probe_child_old_fchownat_dies() {
        if !crate::sys::probe::is("old-fchownat") {
            return;
        }
        rustix::thread::set_no_new_privs(true).expect("nnp");
        install().expect("probe install");
        // fchownat(260) — the filter kills on entry; never returns.
        let _ = audited::fchownat_raw(c"/nonexistent");
        std::process::exit(42);
    }

    /// Parent halves of the R5 T9 syscall-surface probes: the real
    /// post-`harden()` surface exits clean, while the two pre-fix
    /// emissions (`fchmodat`, `statx`) die by `SIGSYS` — the
    /// before/after pair the P0-A fix is pinned by.
    #[test]
    fn broker_surface_and_old_shape_probes() {
        let surface = crate::sys::probe::run_on(
            "sys::seccomp::tests::probe_child_broker_surface",
            "broker-surface",
        );
        assert!(
            surface.success(),
            "broker-surface probe died (P0-A regression): {surface:?}"
        );

        let chmod = crate::sys::probe::run_on(
            "sys::seccomp::tests::probe_child_old_fchmodat_dies",
            "old-fchmodat",
        );
        assert_eq!(
            chmod.signal(),
            Some(libc::SIGSYS),
            "old fchmodat shape must die by SIGSYS, got {chmod:?}"
        );

        let statx = crate::sys::probe::run_on(
            "sys::seccomp::tests::probe_child_old_statx_dies",
            "old-statx",
        );
        assert_eq!(
            statx.signal(),
            Some(libc::SIGSYS),
            "old statx shape must die by SIGSYS, got {statx:?}"
        );

        // Round-2 pins: the emissions `std::fs`/`rustix` path calls
        // reached pre-fix — `rename` (82, unconditional), `unlink`
        // (87), `link` (86), `fchownat` (260) — must all still die.
        for (test, mode, name) in [
            (
                "sys::seccomp::tests::probe_child_old_rename_dies",
                "old-rename",
                "rename",
            ),
            (
                "sys::seccomp::tests::probe_child_old_unlink_dies",
                "old-unlink",
                "unlink",
            ),
            (
                "sys::seccomp::tests::probe_child_old_link_dies",
                "old-link",
                "link",
            ),
            (
                "sys::seccomp::tests::probe_child_old_fchownat_dies",
                "old-fchownat",
                "fchownat",
            ),
        ] {
            let status = crate::sys::probe::run_on(test, mode);
            assert_eq!(
                status.signal(),
                Some(libc::SIGSYS),
                "old {name} shape must die by SIGSYS, got {status:?}"
            );
        }
    }
}
