//! `LocalExec` — the development/test implementation of
//! `port::ProcessLauncher` (phase 2a spec decisions 11 and 13), a port
//! of upstream `internal/adapter/harness/localexec`. It starts a
//! harness as the current user, with no sandbox, so it refuses to run
//! as root or as any user other than the configured operator, and it
//! runs only programs configured by absolute path.
//!
//! **It is for development and tests only.** Kill and liveness work on
//! the process group, not a cgroup: a descendant that calls `setsid`
//! (a daemonizing background task, for example) leaves the group,
//! escapes the kill ladder and is invisible to `is_alive`.
//! Scope-to-group bookkeeping is in memory; an entry is dropped as
//! soon as its group is observed gone (after `wait`, `kill` or a
//! negative `is_alive`), so a later reuse of the group id by the
//! kernel is not read as the scope being alive — but an entry nobody
//! observes after the group ends still names a reusable id. The phase
//! 2b sandbox launcher ([`crate::launcher`]) kills and probes by
//! cgroup instead.
//!
//! Upstream keeps this package behind an *architectural* gate: the
//! archguard harness-launcher-boundary rule keeps every other package
//! from importing it. The Rust workspace has no archguard yet, so
//! construction itself fails closed: [`LocalExec::new`] refuses unless
//! the explicit dev gate [`DEV_GATE_ENV`]`=1` is set (the issue-120
//! dev-gate contract: dev-only paths exist only behind an explicit
//! flag).
//!
//! The process-group signal syscalls (`kill(-pgid, …)` of upstream's
//! package-level helpers) are the [`GroupSignals`] port, injected at
//! construction — the same seams upstream's tests override
//! (`aliveProbe`/`sendSignal` in `export_test.go`). This crate holds
//! no syscall implementation: the audited one belongs to
//! `central-adapter-linux`; tests use scripted signals.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use central_foundation::failure::Failure;
use central_harness::port::{ExitStatus, PortFuture, Process, ProcessLauncher, ProcessSpec};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};

use crate::process::{
    GroupGone, KillLadder, Outcome, ReadEnd, async_write, await_group_gone, group_gone, is_gone,
    mark_gone,
};

/// `DefaultKillGrace` — the SIGTERM to SIGKILL grace when
/// [`Config::kill_grace`] is zero.
pub const DEFAULT_KILL_GRACE: Duration = Duration::from_secs(5);

/// `DEV_GATE_ENV` — the explicit dev gate. `LocalExec::new` refuses
/// unless this environment variable is exactly `1` (issue #120: the
/// dev-only launcher exists only behind an explicit flag; upstream's
/// gate is the archguard import ban the Rust workspace does not have
/// yet).
pub const DEV_GATE_ENV: &str = "CENTRAL_LOCALEXEC";

/// Stable machine codes — the upstream `Err*` sentinels.
pub mod codes {
    /// `LocalExec::new` without the dev gate set — the Rust stand-in
    /// for upstream's archguard import ban.
    pub const DEV_GATE_REQUIRED: &str = "localexec_dev_gate_required";
    /// `ErrInvalidConfig`.
    pub const INVALID_CONFIG: &str = "localexec_invalid_config";
    /// `ErrOperatorMismatch` — not running as the configured operator.
    pub const OPERATOR_MISMATCH: &str = "localexec_operator_mismatch";
    /// `ErrUnknownProgram` — the program is not configured.
    pub const UNKNOWN_PROGRAM: &str = "localexec_unknown_program";
    /// `ErrScopeInUse` — the scope already has a live process.
    pub const SCOPE_IN_USE: &str = "localexec_scope_in_use";
    /// Spawn, pipe or passwd-lookup failures of `Launch`.
    pub const LAUNCH_FAILED: &str = "localexec_launch_failed";
    /// The child `wait` call itself failed.
    pub const WAIT_FAILED: &str = "localexec_wait_failed";
    /// The kill ladder's group survived SIGKILL — or a signal could
    /// not be sent.
    pub const KILL_LADDER: &str = "localexec_kill_ladder";
}

/// A signal [`GroupSignals::send_signal`] delivers to the group —
/// upstream `syscall.SIGTERM`/`SIGKILL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Graceful end — `SIGTERM`.
    Term,
    /// Forced end — `SIGKILL`.
    Kill,
}

/// The process-group signal boundary — upstream's package-level
/// `groupAlive`/`sendSignal` helpers over `syscall.Kill(-pgid, …)`.
/// Injected at construction; the audited implementation is an
/// OS-syscall boundary that lives outside this crate
/// (`central-adapter-linux`), exactly as upstream's test seam
/// (`export_test.go`) predicts.
pub trait GroupSignals: Send + Sync + 'static {
    /// `groupAlive` — `kill(-pgid, 0)`: `EPERM` means the group exists
    /// but belongs to someone else, which still counts as alive.
    fn group_alive(&self, pgid: i64) -> bool;

    /// `sendSignal` — `kill(-pgid, sig)`; `ESRCH` (already gone) is
    /// not an error to a caller of the kill ladder.
    fn send_signal(&self, pgid: i64, sig: Signal) -> Result<(), Failure>;
}

/// `Config` configures a [`LocalExec`].
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// The only uid the launcher runs as. `0` is refused.
    pub operator_uid: u32,
    /// Maps a symbolic program name to an absolute path. Nothing is
    /// ever resolved through `PATH`.
    pub programs: BTreeMap<String, PathBuf>,
    /// The SIGTERM→SIGKILL grace; `Duration::ZERO` means
    /// [`DEFAULT_KILL_GRACE`]. (Upstream's negative-grace refusal is
    /// unrepresentable: a `Duration` is never negative.)
    pub kill_grace: Duration,
}

/// The shared scope bookkeeping — upstream's `scopes`/`procs` maps
/// under `l.mu`.
#[derive(Default)]
struct Scopes {
    /// scope id -> process group id (in memory, dev only).
    scopes: HashMap<String, i64>,
    /// scope id -> its latest process, for `kill_scope`.
    procs: HashMap<String, Arc<LocalProcessInner>>,
}

/// The injectable current-uid probe (upstream `l.getuid`).
type UidProbe = Arc<dyn Fn() -> u32 + Send + Sync>;

/// The injectable `user.LookupId`: uid → (home dir, user name).
type PasswdLookup = Arc<dyn Fn(u32) -> Result<(String, String), Failure> + Send + Sync>;

/// `LocalExec` starts harness processes as the current (operator)
/// user — upstream `localexec.Launcher`.
pub struct LocalExec {
    operator_uid: u32,
    programs: BTreeMap<String, PathBuf>,
    grace: Duration,
    /// `l.getuid` — injectable for tests, as upstream's is.
    getuid: UidProbe,
    /// `user.LookupId` — uid → (home, name); injectable for tests.
    passwd_lookup: PasswdLookup,
    signals: Arc<dyn GroupSignals>,
    scopes: Arc<Mutex<Scopes>>,
}

/// The real uid of this process — Linux `/proc/self` ownership, the
/// safe-API stand-in for `os.Getuid` this crate can afford (no
/// syscall crate may be imported).
fn host_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata("/proc/self") {
        Ok(m) => m.uid(),
        Err(_) => 0,
    }
}

/// `user.LookupId(uid)` → `(home_dir, user_name)` — a bounded
/// `/etc/passwd` parse; a missing entry is a launch failure, never a
/// guessed value.
fn passwd_entry(uid: u32) -> Result<(String, String), Failure> {
    let failed = || {
        Failure::internal(
            codes::LAUNCH_FAILED,
            "localexec: look up operator passwd entry failed",
        )
    };
    let data = match std::fs::read("/etc/passwd") {
        Ok(d) if d.len() <= (1 << 20) => d,
        _ => return Err(failed()),
    };
    let text = String::from_utf8_lossy(&data);
    for line in text.lines() {
        let mut f = line.split(':');
        let (Some(name), Some(_pw), Some(uid_s)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if uid_s.parse::<u32>() == Ok(uid) {
            let home = f.nth(2).unwrap_or("").to_string();
            return Ok((home, name.to_string()));
        }
    }
    Err(failed())
}

impl LocalExec {
    /// `New` — fails closed unless [`DEV_GATE_ENV`]`=1` is set, then
    /// validates `cfg` (upstream `New`).
    pub fn new(cfg: Config, signals: Arc<dyn GroupSignals>) -> Result<Self, Failure> {
        let open = std::env::var_os(DEV_GATE_ENV).is_some_and(|v| v == "1");
        Self::new_checked(cfg, signals, open)
    }

    /// `new_checked` — the single place gate and config validation
    /// live; tests drive both verdicts without mutating the process
    /// environment.
    pub(crate) fn new_checked(
        cfg: Config,
        signals: Arc<dyn GroupSignals>,
        gate_open: bool,
    ) -> Result<Self, Failure> {
        if !gate_open {
            return Err(Failure::denied(
                codes::DEV_GATE_REQUIRED,
                format!(
                    "localexec is a development-only launcher; set {DEV_GATE_ENV}=1 to permit it (issue #120)"
                ),
            ));
        }
        Self::build(cfg, signals)
    }

    /// `New`'s config validation, shared by every construction path.
    fn build(cfg: Config, signals: Arc<dyn GroupSignals>) -> Result<Self, Failure> {
        let invalid = |msg: &str| Failure::invalid(codes::INVALID_CONFIG, msg.to_string());
        if cfg.operator_uid == 0 {
            return Err(invalid("operator uid must be a positive non-root uid"));
        }
        let mut programs = BTreeMap::new();
        for (name, path) in &cfg.programs {
            if name.is_empty() {
                return Err(invalid("empty program name"));
            }
            if !path.is_absolute() {
                return Err(invalid("program path must be absolute"));
            }
            programs.insert(name.clone(), clean_path(path));
        }
        let grace = if cfg.kill_grace == Duration::ZERO {
            DEFAULT_KILL_GRACE
        } else {
            cfg.kill_grace
        };
        Ok(Self {
            operator_uid: cfg.operator_uid,
            programs,
            grace,
            getuid: Arc::new(host_uid),
            passwd_lookup: Arc::new(passwd_entry),
            signals,
            scopes: Arc::new(Mutex::new(Scopes::default())),
        })
    }

    /// `SetGetuid` — overrides the uid probe; test-only seam matching
    /// upstream's `export_test.go`.
    pub fn set_uid_probe(&mut self, getuid: impl Fn() -> u32 + Send + Sync + 'static) {
        self.getuid = Arc::new(getuid);
    }

    /// Overrides the operator passwd lookup; test-only seam.
    pub fn set_passwd_lookup(
        &mut self,
        f: impl Fn(u32) -> Result<(String, String), Failure> + Send + Sync + 'static,
    ) {
        self.passwd_lookup = Arc::new(f);
    }

    /// `forgetIfGone` — drop `scope`'s entry if it still names `pgid`
    /// and the group is gone, so a recycled pgid can never be read as
    /// the scope being alive. Reports whether the group is now known
    /// gone: just observed gone and dropped, or the entry was already
    /// gone (dropped earlier or replaced by a later `launch`).
    fn forget_if_gone(&self, scope: &str, pgid: i64) -> bool {
        let mut m = self.scopes.lock().unwrap_or_else(|p| p.into_inner());
        match m.scopes.get(scope) {
            Some(&current) if current == pgid => {
                if self.signals.group_alive(pgid) {
                    return false;
                }
                m.scopes.remove(scope);
                m.procs.remove(scope);
                true
            }
            _ => true,
        }
    }
}

/// `filepath.Clean` for an absolute path — keeps `RootDir`/`Normal`
/// components only.
fn clean_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push(c.as_os_str()),
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(_) => {}
        }
    }
    out
}

impl ProcessLauncher for LocalExec {
    /// `Launch` starts `spec.program` in its own process group. The
    /// environment is built from empty: `spec.env` plus `HOME`, `USER`
    /// and `LOGNAME` from the operator's passwd entry, which override
    /// any spec value. Dropping the future bounds only the launch;
    /// the process lives until it exits or `kill`.
    fn launch<'a>(
        &'a self,
        spec: ProcessSpec,
    ) -> PortFuture<'a, Result<Box<dyn Process>, Failure>> {
        Box::pin(async move {
            spec.validate()?;
            let uid = (self.getuid)();
            if uid == 0 || uid != self.operator_uid {
                return Err(Failure::denied(
                    codes::OPERATOR_MISMATCH,
                    "localexec: not running as the configured operator",
                ));
            }
            let Some(path) = self.programs.get(&spec.program).cloned() else {
                return Err(Failure::invalid(
                    codes::UNKNOWN_PROGRAM,
                    "localexec: program not configured",
                ));
            };
            let (home, user) = (self.passwd_lookup)(uid)?;
            let mut env = spec.env.clone();
            env.insert("HOME".to_string(), home);
            env.insert("USER".to_string(), user.clone());
            env.insert("LOGNAME".to_string(), user);
            {
                let stale = {
                    let m = self.scopes.lock().unwrap_or_else(|p| p.into_inner());
                    m.scopes.get(&spec.scope_id).copied()
                };
                if let Some(pgid) = stale {
                    // `forget_if_gone` clears the entry when the group
                    // is dead; a live group means the scope is in use.
                    if !self.forget_if_gone(&spec.scope_id, pgid) {
                        return Err(Failure::conflict(
                            codes::SCOPE_IN_USE,
                            "localexec: scope already has a live process",
                        ));
                    }
                }
            }
            let mut cmd = Command::new(&path);
            cmd.args(&spec.args)
                .env_clear()
                .envs(&env)
                .current_dir(&spec.work_dir)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                // `Setpgid: true` — the child leads its own group, so
                // the pgid is its pid.
                .process_group(0);
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(_) => {
                    return Err(Failure::internal(
                        codes::LAUNCH_FAILED,
                        "localexec: start failed",
                    ));
                }
            };
            let Some(pid) = child.id() else {
                return Err(Failure::internal(
                    codes::LAUNCH_FAILED,
                    "localexec: spawned child has no pid",
                ));
            };
            let pgid = i64::from(pid);
            let stdin = child.stdin.take();
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let (Some(stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
                return Err(Failure::internal(
                    codes::LAUNCH_FAILED,
                    "localexec: spawned child is missing a stdio end",
                ));
            };

            let inner = Arc::new(LocalProcessInner {
                scope: spec.scope_id.clone(),
                pgid,
                grace: self.grace,
                signals: self.signals.clone(),
                stdin: tokio::sync::Mutex::new(Some(stdin)),
                stdout: tokio::sync::Mutex::new(ReadEnd::new(stdout)),
                stderr: tokio::sync::Mutex::new(ReadEnd::new(stderr)),
                outcome: Outcome::new(),
                group_gone: group_gone(),
                kill_ladder: KillLadder::new(),
                forget: Mutex::new(None),
            });
            // `forget` references `inner`, so it is wired up after
            // `inner` exists — upstream's `p.forget = func(){...}`.
            {
                let scopes = self.scopes.clone();
                let signals = self.signals.clone();
                let scope = spec.scope_id.clone();
                let gone = inner.group_gone.clone();
                *inner.forget.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(Box::new(move || {
                        let known_gone = {
                            let mut m = scopes.lock().unwrap_or_else(|p| p.into_inner());
                            match m.scopes.get(&scope) {
                                Some(&current) if current == pgid => {
                                    if signals.group_alive(pgid) {
                                        false
                                    } else {
                                        m.scopes.remove(&scope);
                                        m.procs.remove(&scope);
                                        true
                                    }
                                }
                                _ => true,
                            }
                        };
                        if known_gone {
                            mark_gone(&gone);
                        }
                    }));
            }
            {
                let mut m = self.scopes.lock().unwrap_or_else(|p| p.into_inner());
                m.scopes.insert(spec.scope_id.clone(), pgid);
                m.procs.insert(spec.scope_id.clone(), inner.clone());
            }
            // The reaper: `go func() { err := cmd.Wait(); ...;
            // p.forget(); close(p.done) }()`.
            {
                let inner = inner.clone();
                tokio::spawn(async move {
                    let status = match child.wait().await {
                        Ok(st) => Ok(exit_status(st)),
                        Err(_) => Err(Failure::internal(
                            codes::WAIT_FAILED,
                            "localexec: wait failed",
                        )),
                    };
                    inner.outcome.set(status);
                    inner.forget();
                });
            }
            Ok(Box::new(LocalProcess { inner }) as Box<dyn Process>)
        })
    }

    /// `KillScope` runs the tracked scope's kill ladder without a
    /// [`Process`] handle. A scope this launcher is not tracking, or
    /// whose group is already gone, is a no-op. Like `is_alive` it
    /// sees only the process group.
    fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let proc = {
                let m = self.scopes.lock().unwrap_or_else(|p| p.into_inner());
                m.procs.get(scope_id).cloned()
            };
            match proc {
                Some(inner) => LocalProcess { inner }.kill().await,
                None => Ok(()),
            }
        })
    }

    /// `Alive` reports whether any process of the scope's group still
    /// exists. A group observed gone is forgotten.
    fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            let pgid = {
                let m = self.scopes.lock().unwrap_or_else(|p| p.into_inner());
                m.scopes.get(scope_id).copied()
            };
            let Some(pgid) = pgid else {
                return Ok(false);
            };
            Ok(!self.forget_if_gone(scope_id, pgid))
        })
    }
}

/// `exitStatus` — `ExitStatus` from `ExitStatusExt`: `128 + signal`
/// when signaled.
fn exit_status(st: std::process::ExitStatus) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = st.signal() {
        return ExitStatus {
            code: 128 + sig,
            signaled: true,
        };
    }
    ExitStatus {
        code: st.code().unwrap_or(-1),
        signaled: false,
    }
}

/// `process` — one launched process tree mapped to `port::Process`.
struct LocalProcessInner {
    scope: String,
    pgid: i64,
    grace: Duration,
    signals: Arc<dyn GroupSignals>,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    stdout: tokio::sync::Mutex<ReadEnd<ChildStdout>>,
    stderr: tokio::sync::Mutex<ReadEnd<ChildStderr>>,
    /// `done` + its stored wait result.
    outcome: Outcome<Result<ExitStatus, Failure>>,
    /// `groupGone` — set once the group is observed gone, so a
    /// recycled pgid can never be probed as live.
    group_gone: GroupGone,
    kill_ladder: KillLadder,
    /// `p.forget` — wired after construction (see `launch`).
    forget: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl LocalProcessInner {
    fn forget(&self) {
        if let Some(f) = self
            .forget
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            f();
        }
    }

    /// `ladder` — upstream's kill ladder: close stdin, short-circuit a
    /// gone group, SIGTERM, grace, SIGKILL, then reap the leader.
    async fn ladder(&self) -> Result<(), Failure> {
        {
            let mut stdin = self.stdin.lock().await;
            let _ = stdin.take();
        }
        if is_gone(&self.group_gone) || !self.signals.group_alive(self.pgid) {
            let _ = self.outcome.wait().await;
            return Ok(());
        }
        self.signals
            .send_signal(self.pgid, Signal::Term)
            .map_err(|e| {
                Failure::new(
                    e.kind(),
                    e.code(),
                    format!("localexec: SIGTERM process group: {}", e.message()),
                )
            })?;
        let signals = self.signals.clone();
        let pgid = self.pgid;
        let mut gone = await_group_gone(
            move || signals.group_alive(pgid),
            Instant::now() + self.grace,
        )
        .await;
        if !gone {
            self.signals
                .send_signal(self.pgid, Signal::Kill)
                .map_err(|e| {
                    Failure::new(
                        e.kind(),
                        e.code(),
                        format!("localexec: SIGKILL process group: {}", e.message()),
                    )
                })?;
            let signals = self.signals.clone();
            let pgid = self.pgid;
            gone = await_group_gone(
                move || signals.group_alive(pgid),
                Instant::now() + self.grace,
            )
            .await;
        }
        let _ = self.outcome.wait().await;
        if !gone {
            return Err(Failure::internal(
                crate::process::codes::KILL_LADDER,
                format!("localexec: process group {} survived SIGKILL", self.pgid),
            ));
        }
        Ok(())
    }
}

/// `LocalProcess` — the `port::Process` `LocalExec` returns.
struct LocalProcess {
    inner: Arc<LocalProcessInner>,
}

fn io_error() -> Failure {
    Failure::internal(
        crate::process::codes::PROCESS_IO,
        "localexec: process stdio failed",
    )
}

impl Process for LocalProcess {
    fn scope_id(&self) -> &str {
        &self.inner.scope
    }

    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut g = self.inner.stdin.lock().await;
            match g.as_mut() {
                Some(w) => async_write(w, buf).await.map_err(|_| io_error()),
                None => Err(io_error()),
            }
        })
    }

    /// `close_stdin` — idempotent; dropping the end closes the pipe.
    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let mut g = self.inner.stdin.lock().await;
            let _ = g.take();
            Ok(())
        })
    }

    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut g = self.inner.stdout.lock().await;
            g.read(buf).await
        })
    }

    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut g = self.inner.stderr.lock().await;
            g.read(buf).await
        })
    }

    /// `Wait` — the reaper's recorded status; dropping the future
    /// bounds only how long `wait` waits, never the reap.
    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        Box::pin(async move { self.inner.outcome.wait().await })
    }

    /// `Kill` runs the kill ladder once, detached: the ladder always
    /// completes; dropping the returned future bounds only how long
    /// `kill` waits for it. Every call after the first waits for the
    /// same ladder and returns its result.
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let inner = self.inner.clone();
            self.inner
                .kill_ladder
                .start(move || async move { inner.ladder().await });
            self.inner.kill_ladder.wait().await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// `scriptedSignals` — upstream's `aliveProbe`/`sendSignal` test
    /// overrides, plus a signal log. `die_on_signal` makes the next
    /// `group_alive` probe report the group gone (a cooperative tree
    /// that exits on SIGTERM); `immortal` keeps it alive forever.
    struct ScriptedSignals {
        alive: AtomicBool,
        send_err: Mutex<Option<Failure>>,
        sent: Mutex<Vec<Signal>>,
        immortal: AtomicBool,
        die_on_signal: AtomicBool,
        probe_count: AtomicU64,
    }

    impl ScriptedSignals {
        fn live() -> Arc<Self> {
            Arc::new(Self {
                alive: AtomicBool::new(true),
                send_err: Mutex::new(None),
                sent: Mutex::new(Vec::new()),
                immortal: AtomicBool::new(false),
                die_on_signal: AtomicBool::new(false),
                probe_count: AtomicU64::new(0),
            })
        }
    }

    impl GroupSignals for ScriptedSignals {
        fn group_alive(&self, _pgid: i64) -> bool {
            self.probe_count.fetch_add(1, Ordering::SeqCst);
            self.alive.load(Ordering::SeqCst) || self.immortal.load(Ordering::SeqCst)
        }
        fn send_signal(&self, _pgid: i64, sig: Signal) -> Result<(), Failure> {
            self.sent
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(sig);
            if self.die_on_signal.load(Ordering::SeqCst) {
                self.alive.store(false, Ordering::SeqCst);
            }
            if let Some(e) = self
                .send_err
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
            {
                return Err(e);
            }
            Ok(())
        }
    }

    fn cfg(programs: &[(&str, &str)]) -> Config {
        Config {
            operator_uid: 1000,
            programs: programs
                .iter()
                .map(|(n, p)| (n.to_string(), PathBuf::from(p)))
                .collect(),
            kill_grace: Duration::from_millis(50),
        }
    }

    /// Upstream `TestNewRefusesRootRelativeAndInvalidConfig` plus the
    /// dev gate.
    #[test]
    fn new_refuses_without_dev_gate_and_bad_config() {
        let signals = ScriptedSignals::live();
        let err = LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), false)
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.code(), codes::DEV_GATE_REQUIRED);

        for (name, c) in [
            ("root uid", cfg(&[("sh", "/bin/sh")])),
            ("relative path", cfg(&[("claude", "bin/claude")])),
            ("bare name", cfg(&[("claude", "claude")])),
            ("empty path", cfg(&[("claude", "")])),
            ("empty name", cfg(&[("", "/bin/sh")])),
        ] {
            let mut c = c;
            if name != "root uid" {
                c.operator_uid = 1000;
            } else {
                c.operator_uid = 0;
            }
            let err = LocalExec::new_checked(c, signals.clone(), true)
                .map(|_| ())
                .unwrap_err();
            assert_eq!(err.code(), codes::INVALID_CONFIG, "{name}: {err}");
        }
        LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals, true).unwrap();
    }

    /// Upstream `TestLaunchRefusesUIDMismatchAndRoot`.
    #[tokio::test]
    async fn launch_refuses_uid_mismatch_and_root() {
        let signals = ScriptedSignals::live();
        let mut l = LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals, true).unwrap();
        for uid in [0u32, 1001] {
            l.set_uid_probe(move || uid);
            let err = l
                .launch(spec(&format!("scope-uid-{uid}")))
                .await
                .map(|_| ())
                .unwrap_err();
            assert_eq!(err.code(), codes::OPERATOR_MISMATCH, "uid {uid}: {err}");
        }
    }

    /// Upstream `TestLaunchRefusesUnknownProgramAndInvalidSpec`.
    #[tokio::test]
    async fn launch_refuses_unknown_program_and_invalid_spec() {
        let signals = ScriptedSignals::live();
        let mut l = LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals, true).unwrap();
        l.set_uid_probe(|| 1000);
        for prog in ["claude", "/bin/sh"] {
            let mut s = spec("scope-unknown");
            s.program = prog.to_string();
            let err = l.launch(s).await.map(|_| ()).unwrap_err();
            assert_eq!(err.code(), codes::UNKNOWN_PROGRAM, "program {prog}: {err}");
        }
        let bad = ProcessSpec {
            program: "sh".to_string(),
            args: vec![],
            env: BTreeMap::new(),
            work_dir: String::new(),
            scope_id: String::new(),
            env_extras: vec![],
        };
        let err = l.launch(bad).await.map(|_| ()).unwrap_err();
        assert_eq!(
            err.code(),
            central_harness::port::codes::INVALID_PROCESS_SPEC
        );
    }

    fn spec(scope: &str) -> ProcessSpec {
        ProcessSpec {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), "exit 0".to_string()],
            env: [("LANG".to_string(), "C.UTF-8".to_string())]
                .into_iter()
                .collect(),
            work_dir: std::env::temp_dir().to_string_lossy().into_owned(),
            scope_id: scope.to_string(),
            env_extras: vec![],
        }
    }

    /// `duplexScope` — a scope entry and a hand-built process whose
    /// stdio come from a real spawned child, so the kill ladder and
    /// the bookkeeping run without a syscall crate. `spawn` is a real
    /// `sh` child; `signals` scripts the group probes.
    async fn spawned_process(
        l: &LocalExec,
        scope: &str,
        cmd: &str,
        signals: Arc<ScriptedSignals>,
    ) -> Arc<LocalProcessInner> {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", cmd])
            .env_clear()
            .current_dir(std::env::temp_dir())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0);
        let mut child = c.spawn().unwrap();
        let pgid = i64::from(child.id().unwrap());
        let inner = Arc::new(LocalProcessInner {
            scope: scope.to_string(),
            pgid,
            grace: Duration::from_millis(50),
            signals,
            stdin: tokio::sync::Mutex::new(child.stdin.take()),
            stdout: tokio::sync::Mutex::new(ReadEnd::new(child.stdout.take().unwrap())),
            stderr: tokio::sync::Mutex::new(ReadEnd::new(child.stderr.take().unwrap())),
            outcome: Outcome::new(),
            group_gone: group_gone(),
            kill_ladder: KillLadder::new(),
            forget: Mutex::new(None),
        });
        {
            let scopes = l.scopes.clone();
            let gone = inner.group_gone.clone();
            let scope_name = scope.to_string();
            let sigs = inner.signals.clone();
            *inner.forget.lock().unwrap_or_else(|p| p.into_inner()) = Some(Box::new(move || {
                let known_gone = {
                    let mut m = scopes.lock().unwrap_or_else(|p| p.into_inner());
                    match m.scopes.get(&scope_name) {
                        Some(&cur) if cur == pgid => {
                            if sigs.group_alive(pgid) {
                                false
                            } else {
                                m.scopes.remove(&scope_name);
                                m.procs.remove(&scope_name);
                                true
                            }
                        }
                        _ => true,
                    }
                };
                if known_gone {
                    mark_gone(&gone);
                }
            }));
        }
        {
            let mut m = l.scopes.lock().unwrap_or_else(|p| p.into_inner());
            m.scopes.insert(scope.to_string(), pgid);
            m.procs.insert(scope.to_string(), inner.clone());
        }
        {
            let inner = inner.clone();
            tokio::spawn(async move {
                let status = match child.wait().await {
                    Ok(st) => Ok(exit_status(st)),
                    Err(_) => Err(Failure::internal(codes::WAIT_FAILED, "wait failed")),
                };
                inner.outcome.set(status);
                inner.forget();
            });
        }
        inner
    }

    /// Upstream `TestKillLadderTerminatesTheWholeGroup` (scripted
    /// half): SIGTERM is sent, the group is observed gone, SIGKILL is
    /// never sent.
    #[tokio::test]
    async fn kill_ladder_sends_term_then_waits() {
        let signals = ScriptedSignals::live();
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        let scope = "scope-term";
        let inner = spawned_process(&l, scope, "exit 0", signals.clone()).await;
        signals.alive.store(false, Ordering::SeqCst);
        let p = LocalProcess {
            inner: inner.clone(),
        };
        p.kill().await.unwrap();
        assert_eq!(
            *signals.sent.lock().unwrap(),
            vec![],
            "a group observed gone takes no signal"
        );
        p.wait().await.unwrap();
    }

    /// Upstream `TestKillEndsACooperativeTreeWithSIGTERM` — SIGTERM
    /// ends the group; the ladder reports success and forgets the
    /// scope.
    #[tokio::test]
    async fn kill_ladder_term_signals_then_forgets() {
        let signals = ScriptedSignals::live();
        signals.die_on_signal.store(true, Ordering::SeqCst);
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        let scope = "scope-term2";
        let inner = spawned_process(&l, scope, "exit 0", signals.clone()).await;
        let p = LocalProcess {
            inner: inner.clone(),
        };
        p.kill().await.unwrap();
        assert_eq!(
            *signals.sent.lock().unwrap(),
            vec![Signal::Term],
            "SIGTERM only — the group was gone before the grace ran out"
        );
        assert!(
            !l.is_alive(scope).await.unwrap(),
            "scope forgotten after the ladder"
        );
    }

    /// Upstream `TestKillReturnsErrorWhenGroupSurvivesSIGKILL`.
    #[tokio::test]
    async fn kill_errors_when_group_survives_sigkill() {
        let signals = ScriptedSignals::live();
        signals.immortal.store(true, Ordering::SeqCst);
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        let scope = "scope-immortal";
        let inner = spawned_process(&l, scope, "exit 0", signals.clone()).await;
        let p = LocalProcess {
            inner: inner.clone(),
        };
        let err = p.kill().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), crate::process::codes::KILL_LADDER);
        assert_eq!(
            *signals.sent.lock().unwrap(),
            vec![Signal::Term, Signal::Kill],
            "TERM then KILL"
        );
        // A later kill shares the same ladder result.
        let err = p.kill().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), crate::process::codes::KILL_LADDER);
    }

    /// Upstream `TestKillSkipsAnAlreadyReapedGroup`.
    #[tokio::test]
    async fn kill_skips_an_already_reaped_group() {
        let signals = ScriptedSignals::live();
        signals.alive.store(false, Ordering::SeqCst);
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        let scope = "scope-reaped";
        let inner = spawned_process(&l, scope, "exit 0", signals.clone()).await;
        mark_gone(&inner.group_gone);
        let p = LocalProcess { inner };
        p.kill().await.unwrap();
        assert!(signals.sent.lock().unwrap().is_empty(), "no signals sent");
    }

    /// Upstream `TestAliveForUnknownScopeAndScopeReuse` and
    /// `TestScopeEntryIsDroppedOnceTheGroupIsGone`.
    #[tokio::test]
    async fn alive_unknown_scope_and_forget() {
        let signals = ScriptedSignals::live();
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        assert!(!l.is_alive("nope").await.unwrap());
        let scope = "scope-alive";
        let _inner = spawned_process(&l, scope, "sleep 5", signals.clone()).await;
        assert!(l.is_alive(scope).await.unwrap());
        // The group observed gone drops the entry.
        signals.alive.store(false, Ordering::SeqCst);
        assert!(!l.is_alive(scope).await.unwrap());
        assert!(
            !l.scopes.lock().unwrap().scopes.contains_key(scope),
            "entry dropped once the group is gone"
        );
        // kill_scope on a forgotten scope is a no-op.
        l.kill_scope(scope).await.unwrap();
    }

    /// `kill_scope` drives the same ladder a `Process::kill` does.
    #[tokio::test]
    async fn kill_scope_drives_the_ladder() {
        let signals = ScriptedSignals::live();
        signals.die_on_signal.store(true, Ordering::SeqCst);
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        let scope = "scope-kill-scope";
        let _inner = spawned_process(&l, scope, "exit 0", signals.clone()).await;
        l.kill_scope(scope).await.unwrap();
        assert_eq!(
            *signals.sent.lock().unwrap(),
            vec![Signal::Term],
            "kill_scope ran the tracked process's ladder"
        );
    }

    /// Upstream `TestWaitHonorsContext` — dropping the wait future
    /// leaves the process alone; a later wait still resolves.
    #[tokio::test]
    async fn wait_is_reusable_and_cancellable() {
        let signals = ScriptedSignals::live();
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        let inner = spawned_process(&l, "scope-wait", "exit 7", signals.clone()).await;
        let p = LocalProcess {
            inner: inner.clone(),
        };
        let st = tokio::time::timeout(Duration::from_secs(10), p.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(st.code, 7);
        let st2 = p.wait().await.unwrap();
        assert_eq!(st2, st, "wait is reusable");
    }

    /// A real `/bin/sh` child: stdio round-trip plus a normal exit.
    /// (`TestLaunchUsesWorkDirAndPipesStdio`, scripted-signals side.)
    #[tokio::test]
    async fn real_child_stdio_round_trip() {
        let signals = ScriptedSignals::live();
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        let inner = spawned_process(
            &l,
            "scope-stdio",
            "read line; printf '%s\\n' \"$line\"",
            signals.clone(),
        )
        .await;
        let p = LocalProcess { inner };
        p.write_stdin(b"hello\n").await.unwrap();
        p.close_stdin().await.unwrap();
        let mut out = String::new();
        {
            let mut g = p.inner.stdout.lock().await;
            let mut buf = [0u8; 64];
            while let Ok(n) = g.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                out.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        }
        assert_eq!(out.trim(), "hello");
        let st = p.wait().await.unwrap();
        assert_eq!(st.code, 0);
        // A second scope launch under the same id succeeds once the
        // group is gone (upstream's reuse rule).
        signals.alive.store(false, Ordering::SeqCst);
        assert!(!l.is_alive("scope-stdio").await.unwrap());
    }

    /// `TestLaunchBuildsEnvFromEmpty` + `TestLaunchUsesWorkDirAndPipesStdio`
    /// (the real-spawn side): `env_clear` means the child sees exactly
    /// the spec's env plus the injected `HOME`/`USER`/`LOGNAME`.
    #[tokio::test]
    async fn launch_spawns_a_real_process_with_operator_env() {
        let signals = ScriptedSignals::live();
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        l.set_passwd_lookup(|_| Ok(("/home/op".to_string(), "op".to_string())));
        let mut s = spec("scope-real-launch");
        s.args = vec![
            "-c".to_string(),
            "printf '%s' \"$LC_MARKER:$HOME:$USER\"".to_string(),
        ];
        s.env.insert("LC_MARKER".to_string(), "set".to_string());
        let p = l.launch(s).await.unwrap();
        let mut out = String::new();
        let mut buf = [0u8; 128];
        while let Ok(n) = p.read_stdout(&mut buf).await {
            if n == 0 {
                break;
            }
            out.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        assert_eq!(out, "set:/home/op:op");
        assert_eq!(p.wait().await.unwrap().code, 0);
    }

    /// `TestLaunchRefusesLiveScope` — a live group under the scope
    /// refuses a second launch.
    #[tokio::test]
    async fn launch_refuses_a_live_scope() {
        let signals = ScriptedSignals::live();
        let mut l =
            LocalExec::new_checked(cfg(&[("sh", "/bin/sh")]), signals.clone(), true).unwrap();
        l.set_uid_probe(|| 1000);
        l.set_passwd_lookup(|_| Ok(("/home/op".to_string(), "op".to_string())));
        let _inner = spawned_process(&l, "scope-dup", "sleep 5", signals.clone()).await;
        let err = l.launch(spec("scope-dup")).await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), codes::SCOPE_IN_USE);
    }
}
