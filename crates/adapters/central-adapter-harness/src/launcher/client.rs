//! `HostLauncher` — the production `port::ProcessLauncher`, a port of
//! upstream `internal/adapter/harness/hostlauncher`. It launches
//! harnesses through the root `central-harness-launcher` daemon: the
//! daemon, not this code, resolves the program, the operator identity,
//! the mount view and the scope cgroup from its root-owned
//! configuration. This module only maps a `port::ProcessSpec` to the
//! closed LAUNCH request and a launched session to `port::Process`.
//!
//! The transport is injected as [`LauncherClient`] — upstream's narrow
//! `Client` interface (adapted by `harnesslauncher.Client` in
//! `client_linux.go`). [`WireSession`] carries the other reusable half
//! of `client_linux.go`: the `Launch` wait-exit/close state machine
//! over an injected [`FrameConn`]. The concrete `AF_UNIX`/
//! `SOCK_SEQPACKET` + `SCM_RIGHTS` connection, the `SO_PEERCRED` peer
//! check and the descriptor-type inspection are an audited OS-syscall
//! boundary: they land with the socket transport, outside this crate.

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use central_foundation::failure::Failure;
use central_harness::port::{ExitStatus, PortFuture, Process, ProcessLauncher, ProcessSpec};

use crate::launcher::protocol::{
    self, Exit, LaunchRequest, Opcode, Scope, codes, decode_response, parse_scope,
};
use crate::process::{
    KillLadder, ReadEnd, async_shutdown, async_write, clean_path, codes as process_codes,
};

/// `SocketPath` — the fixed, socket-activated launcher socket (spec
/// decision 16), upstream `harnesslauncher.SocketPath`.
pub const SOCKET_PATH: &str = "/run/central-harness-launcher/launcher.sock";

/// `KillGrace` — the SIGTERM grace Kill asks the daemon for (spec
/// decision 15).
pub const KILL_GRACE: Duration = Duration::from_secs(5);

/// `killBudget` bounds the detached KILL request. It covers the
/// daemon's worst case with a margin: a KILL forwarded while the launch
/// is still being set up waits for the setup (up to 30 s), then the
/// grace, the monitor's wait for the init (30 s) and the drain (10 s):
/// 75 s. A KILL taken by a cleaner is bounded at 60 s. Keep it above
/// both when those daemon timeouts change (upstream session.c/main.c).
pub(crate) const KILL_BUDGET: Duration = Duration::from_secs(30 + 5 + 30 + 10 + 10);

/// Stable machine codes for this module — the upstream `Err*` sentinels
/// of `hostlauncher`.
pub mod host_codes {
    /// `ErrInvalidConfig`.
    pub const INVALID_CONFIG: &str = "hostlauncher_invalid_config";
    /// `ErrWorkDirRefused` — the workdir is neither the probe workdir
    /// nor strictly beneath the worktree root.
    pub const WORKDIR_REFUSED: &str = "hostlauncher_workdir_refused";
    /// `ErrInvalidProgram` — the program is not a harness id
    /// (`[a-z0-9-]`, 1–32).
    pub const INVALID_PROGRAM: &str = "hostlauncher_invalid_program";
    /// `ErrInvalidScope` — the scope id is not a canonical non-nil UUID.
    pub const INVALID_SCOPE: &str = "hostlauncher_invalid_scope";
}

fn invalid(code: &'static str, msg: impl Into<String>) -> Failure {
    Failure::invalid(code, msg.into())
}

/// `beneath` reports whether `p` lies strictly beneath `root` (both
/// absolute and clean).
fn beneath(root: &Path, p: &Path) -> bool {
    p.strip_prefix(root).is_ok_and(|rel| {
        !rel.as_os_str().is_empty() && rel.components().all(|c| matches!(c, Component::Normal(_)))
    })
}

/// A clean absolute non-root path, as upstream `New` requires
/// (`filepath.IsAbs` plus `filepath.Clean(p) == p`; `/` is refused).
fn clean_absolute(p: &Path) -> bool {
    p.is_absolute() && p != Path::new("/") && clean_path(p) == p
}

/// `validHarness` — the program is a harness id the daemon resolves.
fn valid_harness(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= protocol::MAX_HARNESS
        && p.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// `Config` configures a [`HostLauncher`].
#[derive(Debug, Clone)]
pub struct Config {
    /// The absolute, clean path the daemon's `worktree_root` names.
    pub worktree_root: PathBuf,
    /// The absolute, clean workdir the adapter uses for its version and
    /// auth probes. It must not lie beneath `worktree_root`.
    pub probe_work_dir: PathBuf,
}

/// One started session as the client returns it — upstream
/// `hostlauncher.Session` / `harnesslauncher.Launch`. The caller owns
/// stdin/stdout/stderr; [`LauncherSession::close`] ends only the
/// lifeline (and the pidfd).
///
/// Object-safety: every method takes `&mut self`; [`HostProcess`]
/// serializes access. `wait_exit` must leave the lifeline open when its
/// future is dropped mid-poll — the real session's read cancellation
/// semantics — so a later `wait_exit` still gets EXIT.
pub trait LauncherSession: Send + 'static {
    /// The launch's scope.
    fn scope(&self) -> Scope;

    /// Hands over the harness's stdin write end, once.
    fn take_stdin(&mut self) -> Option<tokio::fs::File>;

    /// Hands over the harness's stdout read end, once.
    fn take_stdout(&mut self) -> Option<tokio::fs::File>;

    /// Hands over the harness's stderr read end, once.
    fn take_stderr(&mut self) -> Option<tokio::fs::File>;

    /// Reads EXIT from the lifeline — upstream `WaitExit`. Once EXIT
    /// (or the lifeline's end) is read, every call returns it. It
    /// never closes the lifeline.
    fn wait_exit(&mut self) -> PortFuture<'_, Result<Exit, Failure>>;

    /// Ends the lifeline — upstream `Close`. Closing the lifeline
    /// before EXIT makes the launcher kill and release the scope.
    /// Idempotent.
    fn close(&mut self);
}

/// The narrow launcher surface [`HostLauncher`] needs — upstream's
/// `hostlauncher.Client` interface, adapted by
/// `harnesslauncher.Client` in production and supplied by fakes in
/// tests.
pub trait LauncherClient: Send + Sync + 'static {
    /// Sends LAUNCH; on success the returned session owns the
    /// connection as the lifeline plus the harness's stdio. The
    /// future bounds only the request: once it resolves, the session
    /// lives until EXIT or close.
    fn launch<'a>(
        &'a self,
        req: LaunchRequest,
    ) -> PortFuture<'a, Result<Box<dyn LauncherSession>, Failure>>;

    /// Whether the scope's cgroup is populated — upstream `Alive`.
    fn alive<'a>(&'a self, scope: Scope) -> PortFuture<'a, Result<bool, Failure>>;

    /// Ends the scope with the KILL ladder — upstream `Kill`.
    fn kill<'a>(&'a self, scope: Scope, grace: Duration) -> PortFuture<'a, Result<(), Failure>>;
}

/// `HostLauncher` implements `port::ProcessLauncher` over a
/// [`LauncherClient`] — upstream `hostlauncher.Launcher`.
pub struct HostLauncher {
    root: PathBuf,
    probe: PathBuf,
    client: std::sync::Arc<dyn LauncherClient>,
}

impl HostLauncher {
    /// Validates `cfg` and returns a launcher — upstream `New`.
    pub fn new(cfg: Config, client: std::sync::Arc<dyn LauncherClient>) -> Result<Self, Failure> {
        for (name, p) in [
            ("worktree root", &cfg.worktree_root),
            ("probe workdir", &cfg.probe_work_dir),
        ] {
            if !clean_absolute(p) {
                return Err(invalid(
                    host_codes::INVALID_CONFIG,
                    format!("{name} must be an absolute, clean, non-root path"),
                ));
            }
        }
        if cfg.probe_work_dir == cfg.worktree_root
            || beneath(&cfg.worktree_root, &cfg.probe_work_dir)
        {
            return Err(invalid(
                host_codes::INVALID_CONFIG,
                "the probe workdir must not lie in the worktree root",
            ));
        }
        Ok(Self {
            root: cfg.worktree_root,
            probe: cfg.probe_work_dir,
            client,
        })
    }

    /// `workDir` maps a spec workdir to the request's workdir field:
    /// the probe workdir maps to empty, a path beneath the worktree
    /// root to its relative form, anything else is refused. Upstream
    /// cleans first (`filepath.Clean`), so an in-bounds path spelled
    /// with `.`/`..` is accepted in its clean form — `/a/b/../probe`
    /// is the probe workdir, not a refusal.
    fn work_dir(&self, wd: &Path) -> Result<String, Failure> {
        let refused = || {
            invalid(
                host_codes::WORKDIR_REFUSED,
                "workdir is neither the probe workdir nor beneath the worktree root",
            )
        };
        if !wd.is_absolute() {
            return Err(refused());
        }
        let wd = clean_path(wd);
        if wd == self.probe {
            return Ok(String::new());
        }
        if !beneath(&self.root, &wd) {
            return Err(refused());
        }
        let rel = wd.strip_prefix(&self.root).map_err(|_| refused())?;
        Ok(rel.to_string_lossy().into_owned())
    }
}

impl ProcessLauncher for HostLauncher {
    /// `Launch` maps spec to a LAUNCH request and starts it. The future
    /// bounds only the request; the session lives until it exits or
    /// Kill.
    fn launch<'a>(
        &'a self,
        spec: ProcessSpec,
    ) -> PortFuture<'a, Result<Box<dyn Process>, Failure>> {
        Box::pin(async move {
            spec.validate()?;
            if !valid_harness(&spec.program) {
                return Err(invalid(
                    host_codes::INVALID_PROGRAM,
                    "program is not a harness id",
                ));
            }
            let scope = parse_scope(&spec.scope_id).map_err(|_| {
                invalid(
                    host_codes::INVALID_SCOPE,
                    "scope id is not a canonical UUID",
                )
            })?;
            let wd = self.work_dir(Path::new(&spec.work_dir))?;
            let mut env: Vec<String> = spec
                .env
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect();
            env.sort();
            let sess = self
                .client
                .launch(LaunchRequest {
                    scope,
                    harness: spec.program.clone(),
                    work_dir: wd,
                    argv: spec.args.clone(),
                    env,
                })
                .await
                .map_err(|e| {
                    Failure::new(
                        e.kind(),
                        e.code(),
                        format!("hostlauncher: launch {}: {}", spec.program, e.message()),
                    )
                })?;
            HostProcess::new(spec.scope_id, scope, self.client.clone(), sess)
                .map(|p| Box::new(p) as Box<dyn Process>)
        })
    }

    /// `Alive` asks the daemon whether the scope's cgroup is populated.
    fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            let scope = parse_scope(scope_id).map_err(|_| {
                invalid(
                    host_codes::INVALID_SCOPE,
                    "scope id is not a canonical UUID",
                )
            })?;
            self.client.alive(scope).await.map_err(|e| {
                Failure::new(
                    e.kind(),
                    e.code(),
                    format!("hostlauncher: alive: {}", e.message()),
                )
            })
        })
    }

    /// `KillScope` asks the daemon to end the scope with the same KILL
    /// ladder as `Process::kill` (SIGTERM through the session's init,
    /// [`KILL_GRACE`], then `cgroup.kill`). The daemon answers a scope
    /// that does not exist with status 0 (PROTOCOL.md: it is already
    /// empty), so a missing scope is a no-op. The caller chooses the
    /// budget (`Process::kill` uses [`KILL_BUDGET`]).
    fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            let scope = parse_scope(scope_id).map_err(|_| {
                invalid(
                    host_codes::INVALID_SCOPE,
                    "scope id is not a canonical UUID",
                )
            })?;
            self.client.kill(scope, KILL_GRACE).await.map_err(|e| {
                Failure::new(
                    e.kind(),
                    e.code(),
                    format!("hostlauncher: kill scope: {}", e.message()),
                )
            })
        })
    }
}

/// `process` — one launched session mapped to `port::Process`.
/// `state` is upstream's `waitMu`: it serializes `wait` callers only.
/// The stdio ends get their own `tokio::sync::Mutex`es — as
/// `LocalProcessInner`'s do — so a `wait` pending on EXIT never blocks
/// `read_stdout`/`read_stderr`: a child that fills a pipe can still be
/// drained to EXIT. The `tokio::sync` guards are `Send`, so the port
/// futures stay `Send`.
struct HostProcess {
    scope_id: String,
    scope: Scope,
    client: std::sync::Arc<dyn LauncherClient>,
    state: tokio::sync::Mutex<ProcessState>,
    stdin: tokio::sync::Mutex<Option<tokio::fs::File>>,
    stdout: tokio::sync::Mutex<ReadEnd<tokio::fs::File>>,
    stderr: tokio::sync::Mutex<ReadEnd<tokio::fs::File>>,
    exited: AtomicBool,
    kill_ladder: KillLadder,
}

/// `waitMu`'s state — the session plus the cached `wait` result.
struct ProcessState {
    sess: Box<dyn LauncherSession>,
    /// `ended` — EXIT or the lifeline's end was read; the lifeline is
    /// closed. `result` caches what `wait` returns from then on.
    ended: bool,
    result: Option<Result<ExitStatus, Failure>>,
}

impl HostProcess {
    fn new(
        scope_id: String,
        scope: Scope,
        client: std::sync::Arc<dyn LauncherClient>,
        mut sess: Box<dyn LauncherSession>,
    ) -> Result<Self, Failure> {
        let missing = || {
            Failure::internal(
                process_codes::PROCESS_IO,
                "launch session is missing a stdio end",
            )
        };
        let stdin = sess.take_stdin().ok_or_else(missing)?;
        let stdout = sess.take_stdout().ok_or_else(missing)?;
        let stderr = sess.take_stderr().ok_or_else(missing)?;
        Ok(Self {
            scope_id,
            scope,
            client,
            state: tokio::sync::Mutex::new(ProcessState {
                sess,
                ended: false,
                result: None,
            }),
            stdin: tokio::sync::Mutex::new(Some(stdin)),
            stdout: tokio::sync::Mutex::new(ReadEnd::new(stdout)),
            stderr: tokio::sync::Mutex::new(ReadEnd::new(stderr)),
            exited: AtomicBool::new(false),
            kill_ladder: KillLadder::new(),
        })
    }
}

fn io_error() -> Failure {
    Failure::internal(process_codes::PROCESS_IO, "process stdio failed")
}

impl Process for HostProcess {
    fn scope_id(&self) -> &str {
        &self.scope_id
    }

    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut g = self.stdin.lock().await;
            match g.as_mut() {
                Some(f) => async_write(f, buf).await.map_err(|_| io_error()),
                None => Err(io_error()),
            }
        })
    }

    /// `close_stdin` — idempotent; dropping the end closes the pipe.
    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            let mut g = self.stdin.lock().await;
            match g.take() {
                Some(mut f) => async_shutdown(&mut f).await.map_err(|_| io_error()),
                None => Ok(()),
            }
        })
    }

    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut g = self.stdout.lock().await;
            g.read(buf).await
        })
    }

    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut g = self.stderr.lock().await;
            g.read(buf).await
        })
    }

    /// `Wait` reads EXIT, then closes the lifeline. Dropping the
    /// returned future before it resolves leaves the lifeline open, so
    /// a later `wait` still gets EXIT — upstream's ctx-cancel path.
    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        Box::pin(async move {
            let mut st = self.state.lock().await;
            if st.ended {
                return match st.result.clone() {
                    Some(r) => r,
                    None => Err(Failure::internal(
                        process_codes::PROCESS_IO,
                        "wait result was already taken",
                    )),
                };
            }
            match st.sess.wait_exit().await {
                Ok(exit) => {
                    let status = ExitStatus {
                        code: exit.code,
                        signaled: exit.signaled,
                    };
                    st.sess.close();
                    st.ended = true;
                    st.result = Some(Ok(status));
                    self.exited.store(true, Ordering::SeqCst);
                    Ok(status)
                }
                Err(e) => {
                    st.sess.close();
                    st.ended = true;
                    let wrapped = Failure::new(
                        e.kind(),
                        e.code(),
                        format!("hostlauncher: wait: {}", e.message()),
                    );
                    st.result = Some(Err(wrapped.clone()));
                    Err(wrapped)
                }
            }
        })
    }

    /// `Kill` asks the daemon to end the scope on its own connection;
    /// the lifeline stays open, so the following `wait` still gets
    /// EXIT. The request runs detached — it always completes even when
    /// the caller drops this future. After EXIT, Kill is a no-op.
    /// Repeated calls wait for the same request.
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            if self.exited.load(Ordering::SeqCst) {
                return Ok(());
            }
            let client = self.client.clone();
            let scope = self.scope;
            self.kill_ladder.start(move || async move {
                match tokio::time::timeout(KILL_BUDGET, client.kill(scope, KILL_GRACE)).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(Failure::new(
                        e.kind(),
                        e.code(),
                        format!("hostlauncher: kill: {}", e.message()),
                    )),
                    Err(_) => Err(Failure::unavailable(
                        "hostlauncher_kill_timeout",
                        "hostlauncher: kill: budget exceeded",
                    )),
                }
            });
            self.kill_ladder.wait().await
        })
    }
}

/// One received datagram: the frame bytes plus its `SCM_RIGHTS`
/// descriptors.
pub type RecvReply = Result<(Vec<u8>, Vec<tokio::fs::File>), Failure>;

/// One CHL1 datagram connection — the transport [`WireSession`] and a
/// `LauncherClient` wire client run over. The concrete
/// `AF_UNIX`/`SOCK_SEQPACKET` + `SCM_RIGHTS` implementation is the
/// audited OS boundary and lands with the socket transport; tests
/// supply scripted fakes.
pub trait FrameConn: Send + 'static {
    /// Sends one request datagram.
    fn send<'a>(&'a mut self, frame: &'a [u8]) -> PortFuture<'a, Result<(), Failure>>;

    /// Receives one datagram and its `SCM_RIGHTS` descriptors.
    /// `Ok((vec![], _))` is the lifeline's end.
    fn receive<'a>(&'a mut self) -> PortFuture<'a, RecvReply>;

    /// Closes the connection — idempotent.
    fn close(&mut self) -> Result<(), Failure>;
}

/// `WireSession` — the `harnesslauncher.Launch` wait-exit/close state
/// machine of `client_linux.go` over an injected [`FrameConn`]: the
/// reusable, socket-free half of the launcher client. The caller owns
/// the stdio ends (handed to it at construction by the transport that
/// decoded the descriptors); `close` ends only the lifeline and the
/// pidfd.
pub struct WireSession {
    scope: Scope,
    stdin: Option<tokio::fs::File>,
    stdout: Option<tokio::fs::File>,
    stderr: Option<tokio::fs::File>,
    pidfd: Option<tokio::fs::File>,
    conn: Box<dyn FrameConn>,

    done: bool,
    exit: Exit,
    err: Option<Failure>,
    closed: bool,
}

impl WireSession {
    /// A session over `conn` (the lifeline) with the already-opened
    /// stdio ends and pidfd — PROTOCOL.md §3.1.2's descriptor set.
    pub fn new(
        scope: Scope,
        conn: Box<dyn FrameConn>,
        stdin: tokio::fs::File,
        stdout: tokio::fs::File,
        stderr: tokio::fs::File,
        pidfd: Option<tokio::fs::File>,
    ) -> Self {
        Self {
            scope,
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
            pidfd,
            conn,
            done: false,
            exit: Exit::default(),
            err: None,
            closed: false,
        }
    }
}

impl LauncherSession for WireSession {
    fn scope(&self) -> Scope {
        self.scope
    }

    fn take_stdin(&mut self) -> Option<tokio::fs::File> {
        self.stdin.take()
    }
    fn take_stdout(&mut self) -> Option<tokio::fs::File> {
        self.stdout.take()
    }
    fn take_stderr(&mut self) -> Option<tokio::fs::File> {
        self.stderr.take()
    }

    /// `WaitExit` reads EXIT from the lifeline. Dropping the future
    /// mid-poll leaves the lifeline open, so a later call still gets
    /// EXIT. Once EXIT (or the lifeline's end) is read, every call
    /// returns it. It never closes the lifeline.
    fn wait_exit(&mut self) -> PortFuture<'_, Result<Exit, Failure>> {
        Box::pin(async move {
            if self.done {
                return match &self.err {
                    Some(e) => Err(e.clone()),
                    None => Ok(self.exit),
                };
            }
            if self.closed {
                return Err(Failure::internal(
                    codes::CLOSED,
                    "harness launcher: launch is closed",
                ));
            }
            match self.conn.receive().await {
                Err(e) => {
                    if self.closed {
                        return Err(Failure::internal(
                            codes::CLOSED,
                            "harness launcher: launch is closed",
                        ));
                    }
                    self.done = true;
                    self.err = Some(e.clone());
                    Err(e)
                }
                Ok((data, fds)) => {
                    // `receivePacket(conn, 0)`: descriptors on the
                    // lifeline are a malformed response — the files
                    // close on drop.
                    if !fds.is_empty() {
                        drop(fds);
                        self.done = true;
                        let e = Failure::internal(
                            codes::MALFORMED_RESPONSE,
                            "harness launcher: lifeline response carried descriptors",
                        );
                        self.err = Some(e.clone());
                        return Err(e);
                    }
                    if data.is_empty() {
                        self.done = true;
                        let e = Failure::internal(
                            codes::LIFELINE_LOST,
                            "harness launcher: lifeline closed without EXIT",
                        );
                        self.err = Some(e.clone());
                        return Err(e);
                    }
                    match decode_response(&data, Opcode::Exit) {
                        Ok(resp) => {
                            self.done = true;
                            self.exit = resp.exit;
                            Ok(self.exit)
                        }
                        Err(e) => {
                            self.done = true;
                            self.err = Some(e.clone());
                            Err(e)
                        }
                    }
                }
            }
        })
    }

    /// `Close` ends the lifeline and drops the pidfd. Closing the
    /// lifeline before EXIT makes the launcher kill and release the
    /// scope. Idempotent; the stdio ends stay the caller's.
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.pidfd = None;
        let _ = self.conn.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    fn pipe() -> (tokio::fs::File, tokio::fs::File) {
        let (r, w) = std::io::pipe().unwrap();
        (
            tokio::fs::File::from_std(std::fs::File::from(std::os::fd::OwnedFd::from(r))),
            tokio::fs::File::from_std(std::fs::File::from(std::os::fd::OwnedFd::from(w))),
        )
    }

    /// `fakeSession` — upstream's fake `Session` for launcher tests.
    struct FakeSession {
        stdin: Option<tokio::fs::File>,
        stdout: Option<tokio::fs::File>,
        stderr: Option<tokio::fs::File>,
        exits: Mutex<VecDeque<Result<Exit, Failure>>>,
        closes: Mutex<usize>,
    }

    impl FakeSession {
        fn script(exits: Vec<Result<Exit, Failure>>) -> Self {
            let (_r0, w0) = pipe();
            let (r1, _w1) = pipe();
            let (r2, _w2) = pipe();
            Self {
                stdin: Some(w0),
                stdout: Some(r1),
                stderr: Some(r2),
                exits: Mutex::new(exits.into()),
                closes: Mutex::new(0),
            }
        }
    }

    impl LauncherSession for FakeSession {
        fn scope(&self) -> Scope {
            Scope([1u8; 16])
        }
        fn take_stdin(&mut self) -> Option<tokio::fs::File> {
            self.stdin.take()
        }
        fn take_stdout(&mut self) -> Option<tokio::fs::File> {
            self.stdout.take()
        }
        fn take_stderr(&mut self) -> Option<tokio::fs::File> {
            self.stderr.take()
        }
        fn wait_exit(&mut self) -> PortFuture<'_, Result<Exit, Failure>> {
            // The std-Mutex guard is dropped before the future runs —
            // holding it across `pending().await` would keep the future
            // from being `Send`.
            let next = {
                let mut q = self.exits.lock().unwrap_or_else(|p| p.into_inner());
                q.pop_front()
            };
            Box::pin(async move {
                match next {
                    Some(r) => r,
                    None => std::future::pending::<Result<Exit, Failure>>().await,
                }
            })
        }
        fn close(&mut self) {
            let mut c = self.closes.lock().unwrap_or_else(|p| p.into_inner());
            *c += 1;
        }
    }

    /// `fakeClient` — upstream's `fakeClient`.
    struct FakeClient {
        sess: Mutex<Option<Box<dyn LauncherSession>>>,
        launch_err: Mutex<Option<Failure>>,
        launched: Mutex<Vec<LaunchRequest>>,
        alive_answer: Mutex<Result<bool, Failure>>,
        kill_err: Mutex<Option<Failure>>,
        killed: Mutex<Vec<(Scope, Duration)>>,
        delay_kill: AtomicBool,
    }

    impl FakeClient {
        fn new() -> Self {
            Self {
                sess: Mutex::new(None),
                launch_err: Mutex::new(None),
                launched: Mutex::new(Vec::new()),
                alive_answer: Mutex::new(Ok(false)),
                kill_err: Mutex::new(None),
                killed: Mutex::new(Vec::new()),
                delay_kill: AtomicBool::new(false),
            }
        }

        fn with_session(sess: Box<dyn LauncherSession>) -> Self {
            let c = Self::new();
            *c.sess.lock().unwrap_or_else(|p| p.into_inner()) = Some(sess);
            c
        }
    }

    impl LauncherClient for FakeClient {
        fn launch<'a>(
            &'a self,
            req: LaunchRequest,
        ) -> PortFuture<'a, Result<Box<dyn LauncherSession>, Failure>> {
            Box::pin(async move {
                self.launched
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(req);
                if let Some(e) = self
                    .launch_err
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                {
                    return Err(e);
                }
                self.sess
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                    .ok_or_else(|| {
                        Failure::internal("fake_no_session", "fake client has no session")
                    })
            })
        }

        fn alive<'a>(&'a self, _scope: Scope) -> PortFuture<'a, Result<bool, Failure>> {
            Box::pin(async move {
                self.alive_answer
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
            })
        }

        fn kill<'a>(
            &'a self,
            scope: Scope,
            grace: Duration,
        ) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async move {
                self.killed
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push((scope, grace));
                if self.delay_kill.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                if let Some(e) = self
                    .kill_err
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                {
                    return Err(e);
                }
                Ok(())
            })
        }
    }

    fn cfg() -> Config {
        Config {
            worktree_root: PathBuf::from("/srv/central/worktrees"),
            probe_work_dir: PathBuf::from("/srv/central/probe"),
        }
    }

    fn spec(work_dir: &str) -> ProcessSpec {
        ProcessSpec {
            program: "claude".to_string(),
            args: vec!["-p".to_string(), "hi".to_string()],
            env: [("LANG".to_string(), "C.UTF-8".to_string())]
                .into_iter()
                .collect(),
            work_dir: work_dir.to_string(),
            scope_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            env_extras: vec![],
        }
    }

    /// Upstream `TestNewValidatesConfig`.
    #[test]
    fn new_validates_config() {
        let client: std::sync::Arc<dyn LauncherClient> = std::sync::Arc::new(FakeClient::new());
        for (name, c) in [
            (
                "relative root",
                Config {
                    worktree_root: PathBuf::from("x/y"),
                    ..cfg()
                },
            ),
            (
                "unclean root",
                Config {
                    worktree_root: PathBuf::from("/srv/../srv/x"),
                    ..cfg()
                },
            ),
            (
                "root /",
                Config {
                    worktree_root: PathBuf::from("/"),
                    ..cfg()
                },
            ),
            (
                "relative probe",
                Config {
                    probe_work_dir: PathBuf::from("x"),
                    ..cfg()
                },
            ),
            (
                "probe == root",
                Config {
                    probe_work_dir: PathBuf::from("/srv/central/worktrees"),
                    ..cfg()
                },
            ),
            (
                "probe beneath root",
                Config {
                    probe_work_dir: PathBuf::from("/srv/central/worktrees/p"),
                    ..cfg()
                },
            ),
        ] {
            let err = HostLauncher::new(c, client.clone())
                .map(|_| ())
                .unwrap_err();
            assert_eq!(err.code(), host_codes::INVALID_CONFIG, "{name}: {err}");
        }
        HostLauncher::new(cfg(), client).unwrap();
    }

    /// Upstream `TestWorkDirMapping`.
    #[tokio::test]
    async fn workdir_mapping() {
        let client = std::sync::Arc::new(FakeClient::with_session(Box::new(FakeSession::script(
            vec![Ok(Exit::default())],
        ))));
        let l = HostLauncher::new(cfg(), client.clone()).unwrap();

        // Probe workdir → empty workdir on the wire.
        l.launch(spec("/srv/central/probe")).await.unwrap();
        assert_eq!(
            client.launched.lock().unwrap().last().unwrap().work_dir,
            "",
            "probe maps to empty workdir"
        );

        // Beneath the root → relative.
        let c2 = std::sync::Arc::new(FakeClient::with_session(Box::new(FakeSession::script(
            vec![Ok(Exit::default())],
        ))));
        let l2 = HostLauncher::new(cfg(), c2.clone()).unwrap();
        l2.launch(spec("/srv/central/worktrees/att-1/repo"))
            .await
            .unwrap();
        assert_eq!(
            c2.launched.lock().unwrap().last().unwrap().work_dir,
            "att-1/repo"
        );

        // Unclean spellings are cleaned first, as upstream's
        // `filepath.Clean`: `..` back into bounds is accepted in its
        // clean form.
        let c3 = std::sync::Arc::new(FakeClient::with_session(Box::new(FakeSession::script(
            vec![Ok(Exit::default())],
        ))));
        let l3 = HostLauncher::new(cfg(), c3.clone()).unwrap();
        l3.launch(spec("/srv/central/worktrees/../probe"))
            .await
            .unwrap();
        assert_eq!(
            c3.launched.lock().unwrap().last().unwrap().work_dir,
            "",
            "an unclean spelling of the probe workdir maps to empty"
        );
        let c4 = std::sync::Arc::new(FakeClient::with_session(Box::new(FakeSession::script(
            vec![Ok(Exit::default())],
        ))));
        let l4 = HostLauncher::new(cfg(), c4.clone()).unwrap();
        l4.launch(spec("/srv/central/worktrees/att-1/./repo"))
            .await
            .unwrap();
        assert_eq!(
            c4.launched.lock().unwrap().last().unwrap().work_dir,
            "att-1/repo",
            "an unclean in-bounds spelling maps to its clean relative"
        );

        // Unrelated paths are refused — including an unclean spelling
        // that cleans out of bounds.
        for wd in [
            "/etc",
            "/srv/central/worktrees",
            "/srv/central/other",
            "rel/path",
            "/srv/central/worktrees/../other",
        ] {
            let err = l2.launch(spec(wd)).await.map(|_| ()).unwrap_err();
            assert_eq!(
                err.code(),
                host_codes::WORKDIR_REFUSED,
                "workdir {wd}: {err}"
            );
        }
    }

    /// Upstream `TestLaunchRefusesBadSpec`.
    #[tokio::test]
    async fn launch_refuses_bad_spec() {
        let client = std::sync::Arc::new(FakeClient::with_session(Box::new(FakeSession::script(
            vec![Ok(Exit::default())],
        ))));
        let l = HostLauncher::new(cfg(), client).unwrap();

        let mut s = spec("/srv/central/probe");
        s.program = "Claude".to_string();
        let err = l.launch(s).await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), host_codes::INVALID_PROGRAM);

        let mut s = spec("/srv/central/probe");
        s.scope_id = "not-a-uuid".to_string();
        let err = l.launch(s).await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), host_codes::INVALID_SCOPE);

        let mut s = spec("/srv/central/probe");
        s.work_dir = String::new();
        let err = l.launch(s).await.map(|_| ()).unwrap_err();
        assert_eq!(
            err.code(),
            central_harness::port::codes::INVALID_PROCESS_SPEC
        );
    }

    /// Upstream `TestWaitReadsExitAndCaches`.
    #[tokio::test]
    async fn wait_reads_exit_and_caches() {
        let sess = FakeSession::script(vec![Ok(Exit {
            code: 137,
            signaled: true,
        })]);
        let client = std::sync::Arc::new(FakeClient::with_session(Box::new(sess)));
        let l = HostLauncher::new(cfg(), client).unwrap();
        let p = l.launch(spec("/srv/central/probe")).await.unwrap();
        let s1 = p.wait().await.unwrap();
        assert_eq!(
            s1,
            ExitStatus {
                code: 137,
                signaled: true
            }
        );
        let s2 = p.wait().await.unwrap();
        assert_eq!(s2, s1, "second wait returns the cached EXIT");
        // Kill after EXIT is a no-op.
        p.kill().await.unwrap();
    }

    /// Regression for the wait/stdio deadlock: a `wait` pending on
    /// EXIT must not block `read_stdout` — `waitMu` serializes waiters
    /// only. A child writing more than a pipe buffer's worth of output
    /// must be drainable to EXIT; holding the wait mutex across
    /// `wait_exit` deadlocked this (the pipe fills, the child never
    /// exits, EXIT never arrives).
    #[tokio::test]
    async fn wait_does_not_block_stdio() {
        let (_r0, w0) = pipe();
        let (r1, mut w1) = pipe();
        let (r2, _w2) = pipe();
        let sess = FakeSession {
            stdin: Some(w0),
            stdout: Some(r1),
            stderr: Some(r2),
            // An empty script pends `wait_exit` forever.
            exits: Mutex::new(VecDeque::new()),
            closes: Mutex::new(0),
        };
        let client = std::sync::Arc::new(FakeClient::with_session(Box::new(sess)));
        let l = HostLauncher::new(cfg(), client).unwrap();
        let p = std::sync::Arc::new(l.launch(spec("/srv/central/probe")).await.unwrap());
        let pw = p.clone();
        let waiter = tokio::spawn(async move { pw.wait().await });
        tokio::task::yield_now().await;
        let payload = vec![b'x'; 128 << 10];
        let want = payload.len();
        let writer = tokio::spawn(async move {
            let mut off = 0usize;
            while off < payload.len() {
                match async_write(&mut w1, &payload[off..]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => off += n,
                }
            }
            off
        });
        let mut got = 0usize;
        let mut buf = [0u8; 8192];
        tokio::time::timeout(Duration::from_secs(15), async {
            while got < want {
                let n = p.read_stdout(&mut buf).await.unwrap();
                assert!(n > 0, "stdout closed early");
                got += n;
            }
        })
        .await
        .expect("read_stdout must not be blocked by a pending wait");
        assert_eq!(writer.await.unwrap(), want);
        waiter.abort();
    }

    /// Upstream `TestKillLeavesLifelineForWait`.
    #[tokio::test]
    async fn kill_leaves_lifeline_for_wait() {
        let sess = FakeSession::script(vec![Ok(Exit {
            code: 143,
            signaled: true,
        })]);
        let client = std::sync::Arc::new(FakeClient::with_session(Box::new(sess)));
        let l = HostLauncher::new(cfg(), client.clone()).unwrap();
        let p = l.launch(spec("/srv/central/probe")).await.unwrap();
        p.kill().await.unwrap();
        assert_eq!(
            client.killed.lock().unwrap()[0].1,
            KILL_GRACE,
            "kill grace = KillGrace"
        );
        let s = p.wait().await.unwrap();
        assert_eq!(s.code, 143, "wait still gets EXIT after kill");
    }

    /// Upstream `TestKillErrorPropagatesToKillNotWait`.
    #[tokio::test]
    async fn kill_error_goes_to_kill_not_wait() {
        let sess = FakeSession::script(vec![Ok(Exit {
            code: 143,
            signaled: true,
        })]);
        let client = std::sync::Arc::new(FakeClient::with_session(Box::new(sess)));
        *client.kill_err.lock().unwrap() =
            Some(Failure::internal(codes::LAUNCH_FAILED, "launch failed"));
        let l = HostLauncher::new(cfg(), client).unwrap();
        let p = l.launch(spec("/srv/central/probe")).await.unwrap();
        let err = p.kill().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), codes::LAUNCH_FAILED);
        p.wait().await.unwrap();
    }

    /// Upstream `TestRepeatedKillSharesOneRequest`.
    #[tokio::test]
    async fn repeated_kill_shares_one_request() {
        let sess = FakeSession::script(vec![Ok(Exit {
            code: 143,
            signaled: true,
        })]);
        let client = std::sync::Arc::new(FakeClient::with_session(Box::new(sess)));
        client.delay_kill.store(true, Ordering::SeqCst);
        let l = HostLauncher::new(cfg(), client.clone()).unwrap();
        let p = l.launch(spec("/srv/central/probe")).await.unwrap();
        let p = std::sync::Arc::new(p);
        let (r1, r2) = tokio::join!(p.kill(), p.kill());
        r1.unwrap();
        r2.unwrap();
        assert_eq!(
            client.killed.lock().unwrap().len(),
            1,
            "one KILL request for two Kill calls"
        );
    }

    /// Upstream `TestAliveAndKillScopeValidateScope`.
    #[tokio::test]
    async fn alive_and_kill_scope_validate_scope() {
        let client = std::sync::Arc::new(FakeClient::new());
        let l = HostLauncher::new(cfg(), client.clone()).unwrap();
        let err = l.is_alive("bad").await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), host_codes::INVALID_SCOPE);
        let err = l.kill_scope("bad").await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), host_codes::INVALID_SCOPE);
        *client.alive_answer.lock().unwrap() = Ok(true);
        assert!(
            l.is_alive("01234567-89ab-cdef-0123-456789abcdef")
                .await
                .unwrap()
        );
        l.kill_scope("01234567-89ab-cdef-0123-456789abcdef")
            .await
            .unwrap();
        assert_eq!(client.killed.lock().unwrap().len(), 1);
    }

    /// `scriptedConn` — a `FrameConn` fake for `WireSession` tests.
    struct ScriptedConn {
        receives: Mutex<VecDeque<RecvReply>>,
        closes: Mutex<usize>,
    }

    impl FrameConn for ScriptedConn {
        fn send<'a>(&'a mut self, _frame: &'a [u8]) -> PortFuture<'a, Result<(), Failure>> {
            Box::pin(async { Ok(()) })
        }
        fn receive<'a>(&'a mut self) -> PortFuture<'a, RecvReply> {
            let next = {
                let mut q = self.receives.lock().unwrap_or_else(|p| p.into_inner());
                q.pop_front()
            };
            Box::pin(async move {
                match next {
                    Some(r) => r,
                    None => std::future::pending().await,
                }
            })
        }
        fn close(&mut self) -> Result<(), Failure> {
            *self.closes.lock().unwrap_or_else(|p| p.into_inner()) += 1;
            Ok(())
        }
    }

    fn wire_session(replies: Vec<RecvReply>) -> WireSession {
        let (_r0, w0) = pipe();
        let (r1, _w1) = pipe();
        let (r2, _w2) = pipe();
        WireSession::new(
            Scope([1u8; 16]),
            Box::new(ScriptedConn {
                receives: Mutex::new(replies.into()),
                closes: Mutex::new(0),
            }),
            w0,
            r1,
            r2,
            None,
        )
    }

    /// `WaitExit` semantics of upstream `client_linux.go`: EXIT caches,
    /// lifeline loss and malformed frames error, closed refuses.
    #[tokio::test]
    async fn wire_session_wait_exit() {
        // EXIT read and cached.
        let frame = protocol::encode_response(&protocol::Response {
            op: Opcode::Exit,
            exit: Exit {
                code: 3,
                signaled: false,
            },
            ..protocol::Response::default()
        })
        .unwrap();
        let mut s = wire_session(vec![Ok((frame, vec![]))]);
        assert_eq!(s.wait_exit().await.unwrap().code, 3);
        assert_eq!(s.wait_exit().await.unwrap().code, 3, "cached EXIT");

        // Lifeline end without EXIT → ErrLifelineLost.
        let mut s = wire_session(vec![Ok((vec![], vec![]))]);
        let err = s.wait_exit().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), codes::LIFELINE_LOST);
        let err = s.wait_exit().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), codes::LIFELINE_LOST, "cached loss");

        // Malformed frame.
        let mut s = wire_session(vec![Ok((b"garbage".to_vec(), vec![]))]);
        let err = s.wait_exit().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), codes::MALFORMED_RESPONSE);

        // Descriptors on the lifeline are a malformed response
        // (`receivePacket(conn, 0)` upstream).
        let (_r, w) = pipe();
        let frame = protocol::encode_response(&protocol::Response {
            op: Opcode::Exit,
            exit: Exit {
                code: 3,
                signaled: false,
            },
            ..protocol::Response::default()
        })
        .unwrap();
        let mut s = wire_session(vec![Ok((frame, vec![w]))]);
        let err = s.wait_exit().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), codes::MALFORMED_RESPONSE);

        // Closed before EXIT → ErrClosed, idempotent close.
        let mut s = wire_session(vec![]);
        s.close();
        s.close();
        let err = s.wait_exit().await.map(|_| ()).unwrap_err();
        assert_eq!(err.code(), codes::CLOSED);
    }
}
