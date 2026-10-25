//! `launcher_linux.go` — `Launch`: validate, build the cgroup subtree,
//! spawn the namespaced `central-agent` child, settle it under the
//! deadline ladder, clean the cgroup up, and report the evidence.
//!
//! The process is born through [`sys::spawn::spawn_namespaced`] — the
//! `clone3` + child trampoline that realizes upstream's `SysProcAttr`:
//! `Cloneflags` (PID/mount/network/cgroup/IPC/UTS namespaces),
//! `Unshareflags` (mount + network), `Credential` 502:502, `Setpgid`,
//! `Noctty`, `Pdeathsig = SIGKILL`, stdin `/dev/null`, stdout/stderr
//! the launcher's stderr. Upstream never moved the child into the
//! cgroup it created — the port uses `CLONE_INTO_CGROUP` so the child
//! is born a member (a `cgroup.procs` write covers kernels without the
//! flag). `MaxFileDescriptors`, which upstream validates but never
//! installs, is installed as `RLIMIT_NOFILE`.

use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use central_foundation::identity::RunId;
use rustix::fs::{FileType, Mode, OFlags, open};
use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitOptions, kill_process, pidfd_send_signal, waitpid};
use time::OffsetDateTime;

use super::domain::{LaunchEvidence, LaunchRequest};
use super::envelope::{AGENT_GID, AGENT_UID, validate_binary, validate_limits};
use crate::sys::{cgroup, namespace::NamespaceFlags, spawn};

/// The launcher's own knobs — the `central-agent` identity and the
/// SIGTERM→SIGKILL grace — on the struct so a test can exercise the
/// launch path against a temporary uid instead of the production
/// constants (which stay [`AGENT_UID`]/[`AGENT_GID`]).
#[derive(Debug, Clone)]
pub struct LauncherConfig {
    /// `setuid` target for the sandboxed child (upstream `agentUID`).
    pub agent_uid: u32,
    /// `setgid` target (upstream `agentGID`).
    pub agent_gid: u32,
    /// SIGTERM → SIGKILL escalation window (upstream 10 s).
    pub grace: Duration,
}

impl Default for LauncherConfig {
    fn default() -> Self {
        Self {
            agent_uid: AGENT_UID,
            agent_gid: AGENT_GID,
            grace: super::settle::DEFAULT_GRACE_PERIOD,
        }
    }
}

fn denied(msg: impl Into<String>) -> Failure {
    Failure::denied("sandbox_denied", msg.into())
}

fn os_failure(step: &str, e: impl std::fmt::Display) -> Failure {
    Failure::internal("sandbox_os", format!("{step}: {e}"))
}

/// `Launch` — validate the envelope, create the cgroup, spawn the
/// namespaced agent child, settle it under `deadline`, and return the
/// evidence. `workspace_root` is the request's delegated workspace
/// descriptor — it must be an open directory (the descriptor-bound
/// contract; upstream's numeric `WorkspaceRootFD` field went unread).
/// It is validated and held for the request's lifetime here; passing
/// it to the child as a working-directory descriptor is the tool-loop
/// slice's composition (upstream gives the child the daemon's cwd).
///
/// # Errors
/// `sandbox_denied` on every envelope/shape refusal (upstream's
/// validation order: limits, then binary, then the descriptor);
/// `sandbox_os` on the cgroup/spawn/settle failures.
pub fn launch(
    cfg: &LauncherConfig,
    req: &LaunchRequest,
    deadline: Duration,
    workspace_root: &OwnedFd,
) -> Result<LaunchEvidence, Failure> {
    validate_limits(&req.resource_limits)?;
    validate_binary(&req.exec_binary)?;
    // The descriptor-bound contract: the attached descriptor must be
    // a directory — a replayed or substituted non-directory refuses.
    let st = rustix::fs::fstat(workspace_root).map_err(|e| os_failure("workspace root stat", e))?;
    if !FileType::from_raw_mode(st.st_mode).is_dir() {
        return Err(denied("sandbox: workspace root is not a directory"));
    }

    // `createCgroup` — the transient subtree upstream writes limits
    // into before the spawn.
    let limits = cgroup::Limits {
        cpu_cores: req.resource_limits.cpu,
        memory_bytes: req.resource_limits.memory_bytes.max(0) as u64,
        max_processes: req.resource_limits.max_processes.max(0) as u32,
    };
    let cg = cgroup::create(RunId::new(), &limits)
        .map_err(|e| Failure::internal(e.code(), format!("sandbox: cgroup: {}", e.message())))?;

    let mut evidence = LaunchEvidence {
        operation_id: req.operation_id.clone(),
        pid: 0,
        resource_limits: req.resource_limits,
        started_at: OffsetDateTime::now_utc(),
        settled_at: None,
        exit_code: None,
        exit_class: String::new(),
        cleanup_result: String::new(),
    };

    let spawned = match spawn_child(cfg, req, &cg) {
        Ok(s) => s,
        Err(e) => {
            cgroup::cleanup(&cg);
            return Err(Failure::internal(
                e.code(),
                format!("sandbox: start: {}", e.message()),
            ));
        }
    };
    evidence.pid = spawned.pid.as_raw_pid();

    // Kernels without CLONE_INTO_CGROUP: join the child by the
    // cgroup.procs write — a failed join means a launched child with no
    // envelope, which is a launch failure, not a partial success.
    if !spawned.cgroup_attached
        && let Err(e) = std::fs::write(cg.join("cgroup.procs"), evidence.pid.to_string())
    {
        signal(&spawned, Signal::KILL);
        let _ = waitpid(Some(spawned.pid), WaitOptions::empty());
        cgroup::cleanup(&cg);
        return Err(os_failure("sandbox: cgroup attach", e));
    }

    // Wait with deadline support — upstream's `select` over `cmd.Wait`
    // and `ctx.Done()`: deadline → SIGTERM → grace → SIGKILL.
    if let Err(e) = settle(&spawned, deadline, cfg.grace, &mut evidence) {
        signal(&spawned, Signal::KILL);
        let _ = waitpid(Some(spawned.pid), WaitOptions::empty());
        cgroup::cleanup(&cg);
        return Err(e);
    }
    cgroup::cleanup(&cg);
    evidence.cleanup_result = if cg.exists() {
        "unclean".to_owned()
    } else {
        "clean".to_owned()
    };
    Ok(evidence)
}

/// Assemble the [`spawn::SpawnSpec`] and spawn — program resolution
/// (`central-agent` → the real path via `PATH`), argv/envp build, the
/// cgroup directory fd for `CLONE_INTO_CGROUP`, the fixed
/// `central-agent` credential, `Pdeathsig = SIGKILL`, `RLIMIT_NOFILE`
/// from `MaxFileDescriptors`.
fn spawn_child(
    cfg: &LauncherConfig,
    req: &LaunchRequest,
    cg: &std::path::Path,
) -> Result<spawn::Spawned, Failure> {
    let program = resolve_program(&req.exec_binary, std::env::var_os("PATH").as_deref())
        .map_err(|e| os_failure("exec", e))?;
    let mut argv = Vec::with_capacity(req.args.len() + 1);
    argv.push(
        CString::new(req.exec_binary.as_str())
            .map_err(|_| denied("sandbox: executable name contains NUL"))?,
    );
    for arg in &req.args {
        argv.push(
            CString::new(arg.as_str()).map_err(|_| denied("sandbox: argument contains NUL"))?,
        );
    }
    // envp is empty — the daemon refuses non-empty request env; an
    // empty environment is what upstream's `cmd.Env = req.Env` with
    // `env: []` produced, and what the closed policy keeps.
    let cgroup_fd = open(
        cg,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| os_failure("cgroup open", e))?;
    let spec = spawn::SpawnSpec {
        program,
        argv,
        env: Vec::new(),
        namespaces: NamespaceFlags::SANDBOX_CREATE,
        unshare: NamespaceFlags::SANDBOX_UNSHARE,
        uid: cfg.agent_uid,
        gid: cfg.agent_gid,
        pdeathsig: Signal::KILL.as_raw(),
        cgroup: Some(cgroup_fd),
        nofile: req.resource_limits.max_file_descriptors.max(0) as u64,
    };
    spawn::spawn_namespaced(&spec)
}

/// `exec.CommandContext`'s LookPath — a name without `/` resolves
/// against `PATH` (the launcher's environment, as upstream's parent-
/// side lookup); the first executable regular file wins. A name with
/// `/` is checked directly — unreachable through `validate_binary`,
/// but the helper stays honest standalone.
fn resolve_program(name: &str, path_env: Option<&std::ffi::OsStr>) -> Result<CString, Failure> {
    use std::os::unix::fs::PermissionsExt as _;
    let executable_file = |p: &std::path::Path| -> bool {
        std::fs::metadata(p)
            .map(|md| md.is_file() && md.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    let resolved = if name.contains('/') {
        executable_file(std::path::Path::new(name)).then(|| std::path::PathBuf::from(name))
    } else {
        path_env.and_then(|env| {
            std::env::split_paths(env)
                .map(|dir| dir.join(name))
                .find(|cand| executable_file(cand))
        })
    };
    match resolved {
        Some(p) => CString::new(p.as_os_str().as_bytes())
            .map_err(|_| Failure::internal("sandbox_os", "resolved program contains NUL")),
        // Upstream `exec.Command`'s ErrNotFound message, verbatim.
        None => Err(Failure::internal(
            "sandbox_os",
            format!("exec: {name:?}: executable file not found in $PATH"),
        )),
    }
}

/// Signal the child — the pidfd when `spawn` could open one (the
/// upstream `cmd.Process.Signal`/`Kill` operations, pidfd-shaped so a
/// recycled pid can never be hit), `kill` otherwise.
fn signal(child: &spawn::Spawned, sig: Signal) {
    match &child.pidfd {
        Some(fd) => {
            let _ = pidfd_send_signal(fd, sig);
        }
        None => {
            let _ = kill_process(child.pid, sig);
        }
    }
}

/// One `waitpid` outcome.
enum Reap {
    /// The child settled — its `WaitStatus`.
    Exited(rustix::process::WaitStatus),
    /// Still running (`WNOHANG`).
    Pending,
    /// `ECHILD` — already reaped or never ours; settle treats it like
    /// a lost child (the `error` class, code 1).
    Gone,
}

/// One `waitpid` — the [`Reap`] shape of the child's state.
fn reap(pid: Pid, opts: WaitOptions) -> Result<Reap, Failure> {
    match waitpid(Some(pid), opts) {
        Ok(Some((_, status))) => Ok(Reap::Exited(status)),
        Ok(None) => Ok(Reap::Pending),
        Err(Errno::CHILD) => Ok(Reap::Gone),
        Err(e) => Err(os_failure("waitpid", e)),
    }
}

/// The settle ladder — upstream's `done` channel + `ctx.Done()` arm:
/// poll `waitpid` at a 10 ms cadence; on the deadline, SIGTERM, then
/// SIGKILL after `grace`, then fill the evidence class exactly as
/// upstream does (exit-0 → `normal` + code; anything else → `error` +
/// code 1; deadline → `deadline` + no code).
fn settle(
    child: &spawn::Spawned,
    deadline: Duration,
    grace: Duration,
    evidence: &mut LaunchEvidence,
) -> Result<(), Failure> {
    let start = Instant::now();
    loop {
        match reap(child.pid, WaitOptions::NOHANG)? {
            Reap::Exited(status) if status.exit_status() == Some(0) => {
                evidence.settled_at = Some(OffsetDateTime::now_utc());
                evidence.exit_code = Some(0);
                evidence.exit_class = "normal".to_owned();
                return Ok(());
            }
            Reap::Exited(_) | Reap::Gone => {
                // Upstream: `cmd.Wait` error → exitCode 1, class
                // error — the real code is discarded the same way.
                evidence.settled_at = Some(OffsetDateTime::now_utc());
                evidence.exit_code = Some(1);
                evidence.exit_class = "error".to_owned();
                return Ok(());
            }
            Reap::Pending => {}
        }
        if start.elapsed() >= deadline {
            signal(child, Signal::TERM);
            let grace_end = Instant::now() + grace;
            while let Reap::Pending = reap(child.pid, WaitOptions::NOHANG)? {
                if Instant::now() >= grace_end {
                    signal(child, Signal::KILL);
                    let _ = reap(child.pid, WaitOptions::empty());
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            evidence.settled_at = Some(OffsetDateTime::now_utc());
            evidence.exit_class = "deadline".to_owned();
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::super::domain::ResourceLimits;
    use super::*;

    fn dir_fd() -> OwnedFd {
        open(
            std::path::Path::new("/tmp"),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open /tmp")
    }

    fn req() -> LaunchRequest {
        LaunchRequest {
            operation_id: "op".to_owned(),
            exec_binary: "central-agent".to_owned(),
            args: Vec::new(),
            env: Vec::new(),
            resource_limits: ResourceLimits::default(),
            deadline_ms: 0,
        }
    }

    /// Validation runs before the cgroup is ever touched: an over-cap
    /// limit is `sandbox_denied`, not an OS error — and the binary
    /// class check fires before the workspace descriptor is read.
    #[test]
    fn validation_order_is_limits_binary_descriptor() {
        let cfg = LauncherConfig::default();
        let ws = dir_fd();
        let mut over = req();
        over.resource_limits.cpu = 2.0;
        over.exec_binary = "/etc/passwd".to_owned();
        let err = launch(&cfg, &over, Duration::from_secs(5), &ws).unwrap_err();
        assert!(
            err.message().contains("exceeds hard cap"),
            "limits first: {}",
            err.message()
        );

        let mut bad = req();
        bad.exec_binary = "/etc/passwd".to_owned();
        let err = launch(&cfg, &bad, Duration::from_secs(5), &ws).unwrap_err();
        assert!(
            err.message().contains("unknown executable class"),
            "binary second: {}",
            err.message()
        );
    }

    /// A non-directory descriptor is the descriptor-bound refusal —
    /// "workspace root is not a directory".
    #[test]
    fn non_directory_workspace_is_denied() {
        let cfg = LauncherConfig::default();
        let path = std::env::temp_dir().join(format!("central-ws-{}", std::process::id()));
        std::fs::write(&path, b"x").expect("temp file");
        let ws: OwnedFd = std::fs::File::open(&path).expect("file fd").into();
        let err = launch(&cfg, &req(), Duration::from_secs(5), &ws).unwrap_err();
        assert_eq!(err.code(), "sandbox_denied");
        assert_eq!(err.message(), "sandbox: workspace root is not a directory");
        std::fs::remove_file(&path).ok();
    }

    /// The envelope checks precede any OS work: a valid request from
    /// an unprivileged caller reaches `sandbox: cgroup:` — proving the
    /// launch path ran and failed at the privileged step.
    #[test]
    fn admission_passes_validation_then_fails_at_cgroup() {
        if rustix::process::geteuid().is_root() {
            return; // root would create the cgroup — skip
        }
        let cfg = LauncherConfig::default();
        let err = launch(&cfg, &req(), Duration::from_secs(5), &dir_fd()).unwrap_err();
        assert!(
            err.message().starts_with("sandbox: cgroup:"),
            "want cgroup-stage refusal, got: {}",
            err.message()
        );
    }

    /// `resolve_program` — PATH search picks the executable file,
    /// misses report upstream's `executable file not found in $PATH`.
    #[test]
    fn resolve_program_searches_path() {
        let dir = std::env::temp_dir().join(format!("central-sp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let exe = dir.join("central-agent");
        std::fs::write(&exe, b"#!/bin/true\n").expect("write");
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        // A non-executable namesake in an earlier dir must not win.
        let earlier = dir.join("earlier");
        std::fs::create_dir_all(&earlier).expect("mkdir2");
        std::fs::write(earlier.join("central-agent"), b"x").expect("write2");
        let path = std::ffi::OsString::from(format!("{}:{}", earlier.display(), dir.display()));
        let found = resolve_program("central-agent", Some(&path)).expect("resolve");
        assert_eq!(found.as_c_str().to_str().unwrap(), exe.to_str().unwrap());
        let err = resolve_program("central-agent-missing", Some(&path)).unwrap_err();
        assert_eq!(
            err.message(),
            "exec: \"central-agent-missing\": executable file not found in $PATH"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
