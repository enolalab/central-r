//! `sys::spawn` — the one process-launch primitive the sandbox
//! launcher composes: a child **born in** upstream's `Cloneflags`
//! namespace set (PID, mount, network, cgroup, IPC, UTS —
//! [`NamespaceFlags::SANDBOX_CREATE`]), optionally born a member of a
//! cgroup v2 subtree (`CLONE_INTO_CGROUP`), which then runs the
//! child-side setup Go's `forkExec` performs for `SysProcAttr`:
//!
//! 1. `unshare(SANDBOX_UNSHARE)` — upstream's `Unshareflags`;
//! 2. `setgroups(0)` + `setgid` + `setuid` — the `central-agent`
//!    `Credential`;
//! 3. `PR_SET_PDEATHSIG` + a `getppid` liveness check — `Pdeathsig
//!    SIGKILL`, closed against the parent-died-before-prctl race the
//!    same way Go does it;
//! 4. `setpgid` + `TIOCNOTTY` — `Setpgid`/`Noctty`;
//! 5. stdin from `/dev/null`, stdout inherited from the launcher's
//!    stderr — `cmd.Stdin = nil; cmd.Stdout = cmd.Stderr = os.Stderr`;
//! 6. `RLIMIT_NOFILE` — upstream's `MaxFileDescriptors` limit, which
//!    upstream *validates* but never installs; the port installs it;
//! 7. `close_range(3..)` — every inherited descriptor except the
//!    error-report pipe goes (upstream relies on CLOEXEC-by-convention;
//!    A06 asks for the enforced form);
//! 8. `execve` on the resolved program with the request's argv and
//!    the (empty-by-policy) env.
//!
//! The clone is `clone3` with `exit_signal = SIGCHLD` so the parent
//! `waitpid`s exactly as upstream's `cmd.Wait` does. Every child setup
//! step reports its `errno` over a close-on-exec pipe before
//! `_exit(127)` — the parent's [`spawn_namespaced`] surfaces the first
//! failure as `sys_spawn_child` and never reports a partial sandbox as
//! a running one.
//!
//! All `unsafe` lives in [`super::audited::clone3_exec`]; this module
//! only assembles POD arguments and validates the pointer contract.

use std::ffi::CString;
use std::io::Read as _;
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;

use central_foundation::failure::Failure;
use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::process::{Pid, WaitOptions, waitpid};

use super::audited;
use super::namespace::NamespaceFlags;
use super::pidfd;

/// `CLONE_INTO_CGROUP` — `<linux/sched.h>` bit 33: the child is born a
/// member of the cgroup v2 directory `clone_args.cgroup` names, with
/// no `cgroup.procs` write window. libc's exported constant is a
/// deprecated overflowing `c_int` literal, so the bit is declared here
/// at the `clone_args.flags` width.
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Everything [`spawn_namespaced`] needs, already translated to
/// C-string form by the caller. Building the `CString`s out here keeps
/// the audited boundary POD-only — the pointer vectors name these
/// strings, which must outlive the call.
#[derive(Debug)]
pub struct SpawnSpec {
    /// The resolved executable path handed to `execve` — absolute by
    /// caller contract (the launcher resolves the `central-agent`
    /// class to a real path before reaching here).
    pub program: CString,
    /// `argv` including `argv[0]` — upstream `exec.CommandContext`'s
    /// name-in-argv[0] convention.
    pub argv: Vec<CString>,
    /// `envp` — empty for the sandbox envelope (the request's `env`
    /// field is denied at the daemon, not filtered here).
    pub env: Vec<CString>,
    /// `clone3` namespace flags — [`NamespaceFlags::SANDBOX_CREATE`].
    pub namespaces: NamespaceFlags,
    /// The child-side `unshare` — [`NamespaceFlags::SANDBOX_UNSHARE`].
    pub unshare: NamespaceFlags,
    /// The `setuid`/`setgid` target — `central-agent` (upstream 502).
    pub uid: u32,
    /// The `setgid` target.
    pub gid: u32,
    /// `PR_SET_PDEATHSIG` signal number — upstream's `SIGKILL`. `0`
    /// disables the check entirely (non-sandbox spawns only).
    pub pdeathsig: i32,
    /// The cgroup-v2 directory descriptor the child is born into
    /// (`CLONE_INTO_CGROUP`), or `None` for the parent's cgroup.
    pub cgroup: Option<OwnedFd>,
    /// `RLIMIT_NOFILE` to install in the child (0 keeps the inherited
    /// limit).
    pub nofile: u64,
}

/// A spawned child, as the parent sees it.
#[derive(Debug)]
pub struct Spawned {
    /// The child's pid in this namespace.
    pub pid: Pid,
    /// A `pidfd` on the child — the signal/liveness handle upstream's
    /// `cmd.Process` stands in for. `None` only when `pidfd_open`
    /// failed (a caller then falls back to `kill`).
    pub pidfd: Option<OwnedFd>,
    /// Whether the child entered `spec.cgroup` at clone time.
    /// `false` means `CLONE_INTO_CGROUP` was refused by the kernel and
    /// the caller must still write the pid to `cgroup.procs`.
    pub cgroup_attached: bool,
}

fn os_failure(step: &str, e: Errno) -> Failure {
    Failure::internal("sys_spawn_os", format!("{step}: {e}"))
}

/// The argv/envp pointer vectors `execve` takes: each entry a
/// `CString` pointer, NULL-terminated at the end.
fn pointer_vector(strings: &[CString]) -> Vec<*const libc::c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect()
}

/// `clone3` + the [`super::audited`] child trampoline, then the
/// error-pipe handshake that turns a child setup failure into a
/// `Result` instead of a silently broken sandbox.
///
/// # Errors
/// `sys_spawn_os` on the `pipe`/`clone3`/`waitpid` failures;
/// `sys_spawn_child` with the child's reported `errno` when any
/// trampoline step fails (`unshare`, credential drop, `prctl`, stdio,
/// `setrlimit`, `close_range`, `execve`).
pub fn spawn_namespaced(spec: &SpawnSpec) -> Result<Spawned, Failure> {
    // The error-report pipe: the write end is CLOEXEC, so a clean
    // execve closes it and the parent's read sees EOF; any earlier
    // failure writes a 4-byte errno first. (`std::io::pipe` + an
    // explicit F_SETFD — the write end's CLOEXEC is the correctness
    // property, so it is set explicitly rather than assumed.)
    let (err_read, err_write) =
        std::io::pipe().map_err(|e| Failure::internal("sys_spawn_os", format!("pipe: {e}")))?;
    fcntl_setfd(&err_write, FdFlags::CLOEXEC).map_err(|e| os_failure("pipe cloexec", e))?;
    let argv = pointer_vector(&spec.argv);
    let envp = pointer_vector(&spec.env);
    let parent_pid = rustix::process::getpid().as_raw_pid();
    let cgroup_raw = spec.cgroup.as_ref().map_or(-1, AsRawFd::as_raw_fd);

    let mut flags = u64::from(spec.namespaces.bits().bits());
    if cgroup_raw >= 0 {
        flags |= CLONE_INTO_CGROUP;
    }
    let exec_spec = |flags: u64, cgroup_fd: i32| audited::CloneExecSpec {
        clone_flags: flags,
        cgroup_fd,
        unshare_flags: u64::from(spec.unshare.bits().bits()),
        uid: spec.uid,
        gid: spec.gid,
        pdeathsig: spec.pdeathsig,
        parent_pid,
        nofile: spec.nofile,
        program: spec.program.as_ptr(),
        argv: argv.as_ptr(),
        envp: envp.as_ptr(),
        err_fd: err_write.as_raw_fd(),
    };

    let (pid, cgroup_attached) = match audited::clone3_exec(&exec_spec(flags, cgroup_raw)) {
        Ok(pid) => (pid, cgroup_raw >= 0),
        // A kernel without CLONE_INTO_CGROUP answers EINVAL; without
        // clone3 entirely, ENOSYS (only reachable off the reference
        // host). Retry once without the flag — the caller then joins
        // the child by writing cgroup.procs.
        Err(e) if cgroup_raw >= 0 && (e == Errno::INVAL || e == Errno::NOSYS) => {
            let pid = audited::clone3_exec(&exec_spec(flags & !CLONE_INTO_CGROUP, -1))
                .map_err(|e2| os_failure("clone3", e2))?;
            (pid, false)
        }
        Err(e) => return Err(os_failure("clone3", e)),
    };
    // The parent's write end must close so the child's execve leaves
    // the reader at EOF.
    drop(err_write);

    if let Some(child_errno) = child_errno(err_read)? {
        // The child already _exit(127)'d; reap so no zombie is left.
        if let Some(pid_val) = Pid::from_raw(pid) {
            let _ = waitpid(Some(pid_val), WaitOptions::empty());
        }
        return Err(Failure::internal(
            "sys_spawn_child",
            format!("sandboxed child setup failed: errno {child_errno}"),
        ));
    }

    let pid_val = Pid::from_raw(pid)
        .ok_or_else(|| Failure::internal("sys_spawn_os", "clone3 returned a non-pid value"))?;
    Ok(Spawned {
        pid: pid_val,
        pidfd: pidfd::open(pid_val).ok(),
        cgroup_attached,
    })
}

/// Read the child's error pipe to EOF: `Some(errno)` when a setup
/// step reported failure, `None` on a clean execve.
fn child_errno(mut err_read: std::io::PipeReader) -> Result<Option<i32>, Failure> {
    let mut buf = [0u8; 4];
    let mut got = 0usize;
    while got < buf.len() {
        match err_read.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(Failure::internal(
                    "sys_spawn_os",
                    format!("read error pipe: {e}"),
                ));
            }
        }
    }
    if got == buf.len() {
        Ok(Some(i32::from_ne_bytes(buf)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{Signal, kill_process};

    /// `/bin/true` under the plain-spawn shape — no namespaces, no
    /// credential change, self uid — exercises the whole clone3 +
    /// trampoline + error-pipe-success path without needing root.
    #[test]
    fn spawn_and_exec_true() {
        let spec = SpawnSpec {
            program: CString::new("/bin/true").expect("program"),
            argv: vec![CString::new("true").expect("argv0")],
            env: Vec::new(),
            namespaces: NamespaceFlags::NONE,
            unshare: NamespaceFlags::NONE,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pdeathsig: 0,
            cgroup: None,
            nofile: 1024,
        };
        let spawned = spawn_namespaced(&spec).expect("spawn true");
        let (_, status) = waitpid(Some(spawned.pid), WaitOptions::empty())
            .expect("waitpid")
            .expect("wait result");
        assert_eq!(status.exit_status(), Some(0));
        assert!(spawned.pidfd.is_some(), "pidfd on live child");
    }

    /// A missing program lands on the error pipe as `ENOENT` — the
    /// child reports, the parent surfaces `sys_spawn_child`, and the
    /// child is reaped (no zombie).
    #[test]
    fn exec_failure_reports_child_errno() {
        let spec = SpawnSpec {
            program: CString::new("/nonexistent/central-t9-probe").expect("program"),
            argv: vec![CString::new("probe").expect("argv0")],
            env: Vec::new(),
            namespaces: NamespaceFlags::NONE,
            unshare: NamespaceFlags::NONE,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pdeathsig: 0,
            cgroup: None,
            nofile: 0,
        };
        let err = spawn_namespaced(&spec).unwrap_err();
        assert_eq!(err.code(), "sys_spawn_child");
        assert!(err.message().contains("2"), "errno in: {}", err.message());
    }

    /// `SANDBOX_CREATE` without `CAP_SYS_ADMIN` fails at the `clone3`
    /// call itself with `EPERM` — the fail-closed envelope the
    /// launcher's privilege gate relies on. Root gets a successful
    /// spawn instead (pid-1-in-new-namespace shape).
    #[test]
    fn sandbox_namespaces_deny_or_spawn() {
        let spec = SpawnSpec {
            program: CString::new("/bin/true").expect("program"),
            argv: vec![CString::new("true").expect("argv0")],
            env: Vec::new(),
            namespaces: NamespaceFlags::SANDBOX_CREATE,
            unshare: NamespaceFlags::SANDBOX_UNSHARE,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pdeathsig: 0,
            cgroup: None,
            nofile: 0,
        };
        match spawn_namespaced(&spec) {
            Ok(spawned) => {
                // Root: the whole trampoline ran — reap the child.
                let (_, status) = waitpid(Some(spawned.pid), WaitOptions::empty())
                    .expect("waitpid")
                    .expect("wait result");
                assert_eq!(status.exit_status(), Some(0));
            }
            Err(e) => {
                // Unprivileged: either the clone3 call fails (EPERM at
                // sys_spawn_os) or a trampoline step fails in the child
                // (sys_spawn_child) — never a silent success.
                assert!(
                    e.code() == "sys_spawn_os" || e.code() == "sys_spawn_child",
                    "unexpected failure class: {e:?}"
                );
            }
        }
    }

    /// R5 T9 P0-B: `SANDBOX_CREATE` carries `CLONE_NEWPID`, so the
    /// child is PID 1 of its new namespace and the kernel reports
    /// `getppid() == 0` for it — a post-`PR_SET_PDEATHSIG` `getppid`
    /// compare against the outer parent pid would `ESRCH` every
    /// sandboxed child before `exec`. The trampoline now skips the
    /// userspace compare only under `NEWPID` (the kernel still tracks
    /// the real parent for the armed signal); this test proves the
    /// child reaches `execve` — `/bin/true` exits 0.
    ///
    /// Root-gated: namespace creation needs `CAP_SYS_ADMIN` (or a
    /// delegated userns the reference host supplies); on other hosts
    /// the skip mirrors `sandbox_namespaces_deny_or_spawn`.
    #[test]
    fn newpid_pdeathsig_child_reaches_exec() {
        if !rustix::process::geteuid().is_root() {
            return;
        }
        let spec = SpawnSpec {
            program: CString::new("/bin/true").expect("program"),
            argv: vec![CString::new("true").expect("argv0")],
            env: Vec::new(),
            namespaces: NamespaceFlags::SANDBOX_CREATE,
            unshare: NamespaceFlags::SANDBOX_UNSHARE,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pdeathsig: libc::SIGKILL,
            cgroup: None,
            nofile: 0,
        };
        // Pre-fix this returned `sys_spawn_child` with errno ESRCH —
        // the condemned child never reached exec.
        let spawned = spawn_namespaced(&spec).expect("NEWPID+pdeathsig spawn");
        let (_, status) = waitpid(Some(spawned.pid), WaitOptions::empty())
            .expect("waitpid")
            .expect("wait result");
        assert_eq!(
            status.exit_status(),
            Some(0),
            "NEWPID child must reach exec and exit 0"
        );
    }

    /// The non-`NEWPID` compare is kept: a plain spawn whose recorded
    /// `parent_pid` matches the real parent still passes the liveness
    /// gate — the `NEWPID` skip is scoped, not deleted.
    #[test]
    fn pdeathsig_compare_runs_without_newpid() {
        let spec = SpawnSpec {
            program: CString::new("/bin/true").expect("program"),
            argv: vec![CString::new("true").expect("argv0")],
            env: Vec::new(),
            namespaces: NamespaceFlags::NONE,
            unshare: NamespaceFlags::NONE,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pdeathsig: libc::SIGKILL,
            cgroup: None,
            nofile: 0,
        };
        let spawned = spawn_namespaced(&spec).expect("plain pdeathsig spawn");
        let (_, status) = waitpid(Some(spawned.pid), WaitOptions::empty())
            .expect("waitpid")
            .expect("wait result");
        assert_eq!(status.exit_status(), Some(0));
    }

    /// `waitpid` + `kill_process` on the pidfd fallback path: a
    /// spawned sleeper can be SIGKILLed and reaped through the handles
    /// `Spawned` returns.
    #[test]
    fn spawned_child_is_killable_and_reapable() {
        let spec = SpawnSpec {
            program: CString::new("/bin/sleep").expect("program"),
            argv: vec![
                CString::new("sleep").expect("argv0"),
                CString::new("60").expect("argv1"),
            ],
            env: Vec::new(),
            namespaces: NamespaceFlags::NONE,
            unshare: NamespaceFlags::NONE,
            uid: rustix::process::geteuid().as_raw(),
            gid: rustix::process::getegid().as_raw(),
            pdeathsig: 0,
            cgroup: None,
            nofile: 0,
        };
        let spawned = spawn_namespaced(&spec).expect("spawn sleep");
        if let Some(pidfd) = &spawned.pidfd {
            rustix::process::pidfd_send_signal(pidfd, Signal::KILL).expect("pidfd SIGKILL");
        } else {
            kill_process(spawned.pid, Signal::KILL).expect("kill");
        }
        let (_, status) = waitpid(Some(spawned.pid), WaitOptions::empty())
            .expect("waitpid")
            .expect("wait result");
        assert_eq!(status.terminating_signal(), Some(Signal::KILL.as_raw()));
    }
}
