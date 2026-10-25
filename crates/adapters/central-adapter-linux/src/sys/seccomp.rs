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
}
