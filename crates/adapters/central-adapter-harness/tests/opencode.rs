//! `adapter_test.go` + `probe_test.go` + `session_test.go` + the
//! identity half of `opencode_test.go` — the scripted fake-harness
//! tests over the verbatim `testdata/` fixtures. A `ScriptedLauncher`
//! answers the `--version` probe with fixed output and hands every
//! session launch to a scripted in-memory `Process`; the play helpers
//! replay fixture bytes exactly as upstream's `scriptedSession` does.

// Integration-test helpers are not `#[test]`-annotated items, so the
// workspace's `allow-*-in-tests` clippy config does not reach them;
// relax the test-only lints for the whole file (`panic` stays denied
// everywhere — assertions use `assert!`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use central_adapter_harness::opencode::{self, Config, OpenCode};
use central_foundation::failure::Failure;
use central_foundation::identity::HarnessAttemptId;
use central_harness::domain::{Fence, PermissionPolicy, Terminal, TerminalStatus, Workspace};
use central_harness::event::{Event, EventPayload, ToolStatus, Usage, UsageScope};
use central_harness::port::{
    Adapter as _, ExitStatus, LaunchEnv, OperatorInput, PermissionDecision, PortFuture, Process,
    ProcessLauncher, ProcessSpec, ReconcileInput, Session, SessionRef, StartSpec,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/opencode")
        .join(name);
    std::fs::read(p).unwrap()
}

fn start_spec(workdir: &str) -> StartSpec {
    StartSpec {
        attempt: HarnessAttemptId::new(),
        fence: Fence { generation: 1 },
        workspace: Workspace {
            path: workdir.to_string(),
            base_sha: "abc123".to_string(),
        },
        prompt: "marker-prompt- Run the Bash command: echo probe".to_string(),
        model: String::new(),
        permission: PermissionPolicy::Deny,
        limits: Default::default(),
        env: LaunchEnv {
            vars: [
                ("PATH".to_string(), "/usr/bin:/bin".to_string()),
                ("LANG".to_string(), "C.UTF-8".to_string()),
            ]
            .into_iter()
            .collect(),
            sandbox_scope_id: "scope-9".to_string(),
        },
    }
}

fn probe_env() -> LaunchEnv {
    LaunchEnv {
        vars: [
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
        ]
        .into_iter()
        .collect(),
        sandbox_scope_id: "probe-scope".to_string(),
    }
}

static TMPDIR_SEQ: AtomicUsize = AtomicUsize::new(0);

/// `t.TempDir()` — a fresh empty directory per call.
fn tmpdir() -> String {
    let dir = std::env::temp_dir().join(format!(
        "central-opencode-test-{}-{}",
        std::process::id(),
        TMPDIR_SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

// =====================================================================
// session_test.go — the in-memory port.Process and scripted launcher
// =====================================================================

/// `io.ErrClosedPipe` — the stdin write failure a dead pipe reports.
fn io_closed() -> Failure {
    Failure::new(
        central_foundation::failure::FailureKind::Internal,
        "E_IO",
        "stdin closed",
    )
}

/// `scriptedProcess` — an in-memory `port.Process` modeling upstream's
/// `io.Pipe` pair: a `write_stdin` pends until the script attaches a
/// reader or stdin dies, and the script plays stdout bytes, observes
/// stdin, and exits with a status. Stderr carries account-shaped text
/// that must never leak into events or reasons.
struct ScriptedProcess {
    scope: String,
    /// adapter → script (stdin)
    stdin_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    stdin_rx: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    /// `stdinR` has a reader — io.Pipe's write side unblocks only then.
    stdin_attached: AtomicBool,
    stdin_dead: AtomicBool,
    stdin_closed: AtomicBool,
    stdin_gate: Notify,
    /// Every byte the adapter wrote to stdin, in order.
    stdin_got: Mutex<Vec<u8>>,
    /// script → adapter (stdout); `exit` drops the sender for EOF.
    /// Received chunks buffer behind a cursor so reads are memcpy —
    /// per-byte pops make the 16 MiB oversize-frame test take seconds
    /// too long in a debug build.
    stdout_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    stdout_rx: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    stdout_left: Mutex<(Vec<u8>, usize)>,
    stderr: Mutex<Vec<u8>>,
    exited: Notify,
    status: Mutex<Option<ExitStatus>>,
    kills: AtomicUsize,
}

impl ScriptedProcess {
    fn new(scope: &str) -> Arc<Self> {
        let (stdin_tx, stdin_rx) = mpsc::unbounded_channel();
        let (stdout_tx, stdout_rx) = mpsc::unbounded_channel();
        Arc::new(Self {
            scope: scope.to_string(),
            stdin_tx: Mutex::new(Some(stdin_tx)),
            stdin_rx: Mutex::new(Some(stdin_rx)),
            stdin_attached: AtomicBool::new(false),
            stdin_dead: AtomicBool::new(false),
            stdin_closed: AtomicBool::new(false),
            stdin_gate: Notify::new(),
            stdin_got: Mutex::new(Vec::new()),
            stdout_tx: Mutex::new(Some(stdout_tx)),
            stdout_rx: AsyncMutex::new(stdout_rx),
            stdout_left: Mutex::new((Vec::new(), 0)),
            stderr: Mutex::new(b"account: operator-probe@example.com\n".to_vec()),
            exited: Notify::new(),
            status: Mutex::new(None),
            kills: AtomicUsize::new(0),
        })
    }

    /// `take_stdin_rx` — attaches the script's stdin reader, unblocking
    /// `write_stdin` exactly as an `io.Pipe` reader does.
    fn take_stdin_rx(&self) -> mpsc::UnboundedReceiver<Vec<u8>> {
        self.stdin_attached.store(true, Ordering::SeqCst);
        self.stdin_gate.notify_waiters();
        self.stdin_rx.lock().unwrap().take().expect("stdin rx once")
    }

    fn stdin_written(&self) -> Vec<u8> {
        self.stdin_got.lock().unwrap().clone()
    }

    /// `exit` — closes stdout and stdin like upstream's `p.exit`.
    fn exit(&self, status: ExitStatus) {
        let mut st = self.status.lock().unwrap();
        if st.is_some() {
            return;
        }
        *st = Some(status);
        drop(st);
        self.stdout_tx.lock().unwrap().take();
        // Upstream closes `stdinR`, so a writer in flight fails.
        self.stdin_tx.lock().unwrap().take();
        self.stdin_dead.store(true, Ordering::SeqCst);
        self.stdin_gate.notify_waiters();
        self.exited.notify_waiters();
    }

    /// Emit bytes on stdout exactly as given.
    async fn emit_raw(&self, bytes: &[u8]) -> Result<(), ()> {
        if self.status.lock().unwrap().is_some() {
            return Err(());
        }
        let tx = self.stdout_tx.lock().unwrap().clone();
        match tx {
            Some(tx) => tx.send(bytes.to_vec()).map_err(|_| ()),
            None => Err(()),
        }
    }

    async fn exited_wait(&self) {
        loop {
            let n = self.exited.notified();
            if self.status.lock().unwrap().is_some() {
                return;
            }
            n.await;
        }
    }

    fn kill_count(&self) -> usize {
        self.kills.load(Ordering::SeqCst)
    }
}

impl Process for ScriptedProcess {
    fn scope_id(&self) -> &str {
        &self.scope
    }

    /// `write_stdin` — io.Pipe semantics: pends until a reader is
    /// attached or stdin dies; a dead or closed pipe fails the write.
    /// The waiter registers (`enable`) before the flag checks so a
    /// notification can never be lost.
    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            loop {
                let notified = self.stdin_gate.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.stdin_dead.load(Ordering::SeqCst)
                    || self.stdin_closed.load(Ordering::SeqCst)
                {
                    return Err(io_closed());
                }
                if self.stdin_attached.load(Ordering::SeqCst) {
                    break;
                }
                notified.await;
            }
            let tx = self.stdin_tx.lock().unwrap().clone();
            match tx {
                Some(tx) => {
                    self.stdin_got.lock().unwrap().extend_from_slice(buf);
                    tx.send(buf.to_vec())
                        .map(|_| buf.len())
                        .map_err(|_| io_closed())
                }
                None => Err(io_closed()),
            }
        })
    }

    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.stdin_tx.lock().unwrap().take();
            self.stdin_closed.store(true, Ordering::SeqCst);
            self.stdin_gate.notify_waiters();
            Ok(())
        })
    }

    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            loop {
                {
                    let mut left = self.stdout_left.lock().unwrap();
                    let avail = left.0.len() - left.1;
                    if avail > 0 {
                        let n = avail.min(buf.len());
                        buf[..n].copy_from_slice(&left.0[left.1..left.1 + n]);
                        left.1 += n;
                        if left.1 == left.0.len() {
                            left.0.clear();
                            left.1 = 0;
                        }
                        return Ok(n);
                    }
                }
                match self.stdout_rx.lock().await.recv().await {
                    Some(chunk) => {
                        self.stdout_left.lock().unwrap().0.extend_from_slice(&chunk);
                    }
                    None => return Ok(0),
                }
            }
        })
    }

    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut e = self.stderr.lock().unwrap();
            if e.is_empty() {
                return Ok(0);
            }
            let n = e.len().min(buf.len());
            buf[..n].copy_from_slice(&e[..n]);
            e.drain(..n);
            Ok(n)
        })
    }

    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        Box::pin(async move {
            self.exited_wait().await;
            Ok(self.status.lock().unwrap().unwrap_or_default())
        })
    }

    /// `Kill` — the launcher's kill ladder: the tree ends signaled.
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.kills.fetch_add(1, Ordering::SeqCst);
            self.exit(ExitStatus {
                code: 143,
                signaled: true,
            });
            Ok(())
        })
    }
}

/// `staticProcess` — a finished probe process with fixed stdout.
struct StaticProcess {
    scope: String,
    stdout: Mutex<Vec<u8>>,
    stderr: Mutex<Vec<u8>>,
    code: i32,
}

impl Process for StaticProcess {
    fn scope_id(&self) -> &str {
        &self.scope
    }
    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move { Ok(buf.len()) })
    }
    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move { Ok(()) })
    }
    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut o = self.stdout.lock().unwrap();
            if o.is_empty() {
                return Ok(0);
            }
            let n = o.len().min(buf.len());
            buf[..n].copy_from_slice(&o[..n]);
            o.drain(..n);
            Ok(n)
        })
    }
    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            let mut e = self.stderr.lock().unwrap();
            if e.is_empty() {
                return Ok(0);
            }
            let n = e.len().min(buf.len());
            buf[..n].copy_from_slice(&e[..n]);
            e.drain(..n);
            Ok(n)
        })
    }
    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        let code = self.code;
        Box::pin(async move {
            Ok(ExitStatus {
                code,
                signaled: false,
            })
        })
    }
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move { Ok(()) })
    }
}

type Script =
    Box<dyn FnOnce(Arc<ScriptedProcess>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// `scriptedLauncher` — fixed probe output; session launches go to a
/// harness script.
struct ScriptedLauncher {
    launches: Mutex<Vec<ProcessSpec>>,
    version: Mutex<String>,
    version_code: Mutex<i32>,
    alive: Mutex<HashMap<String, bool>>,
    alive_err: Mutex<Option<Failure>>,
    launch_err: Mutex<Option<Failure>>,
    script: Mutex<Option<Script>>,
    sessions: Mutex<Vec<Arc<ScriptedProcess>>>,
}

impl ScriptedLauncher {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            launches: Mutex::new(Vec::new()),
            version: Mutex::new("1.18.32\n".to_string()),
            version_code: Mutex::new(0),
            alive: Mutex::new(HashMap::new()),
            alive_err: Mutex::new(None),
            launch_err: Mutex::new(None),
            script: Mutex::new(Some(script)),
            sessions: Mutex::new(Vec::new()),
        })
    }

    fn unscripted() -> Arc<Self> {
        Self::new(Box::new(|_| Box::pin(async {})))
    }

    fn set_version(&self, v: &str) {
        *self.version.lock().unwrap() = v.to_string();
    }

    fn set_version_out(&self, out: &str, code: i32) {
        self.set_version(out);
        *self.version_code.lock().unwrap() = code;
    }

    fn set_launch_err(&self, e: Failure) {
        *self.launch_err.lock().unwrap() = Some(e);
    }

    fn set_alive(&self, scope: &str, alive: bool) {
        self.alive.lock().unwrap().insert(scope.to_string(), alive);
    }

    fn set_alive_err(&self, e: Failure) {
        *self.alive_err.lock().unwrap() = Some(e);
    }

    fn launches(&self) -> Vec<ProcessSpec> {
        self.launches.lock().unwrap().clone()
    }

    fn last_session(&self) -> Arc<ScriptedProcess> {
        self.sessions.lock().unwrap().last().unwrap().clone()
    }
}

impl ProcessLauncher for ScriptedLauncher {
    fn launch<'a>(
        &'a self,
        spec: ProcessSpec,
    ) -> PortFuture<'a, Result<Box<dyn Process>, Failure>> {
        Box::pin(async move {
            spec.validate()?;
            self.launches.lock().unwrap().push(spec.clone());
            if let Some(e) = self.launch_err.lock().unwrap().clone() {
                return Err(e);
            }
            if spec.args.as_slice() == ["--version"] {
                return Ok(Box::new(StaticProcess {
                    scope: spec.scope_id.clone(),
                    stdout: Mutex::new(self.version.lock().unwrap().as_bytes().to_vec()),
                    stderr: Mutex::new(b"email operator-probe@example.com\n".to_vec()),
                    code: *self.version_code.lock().unwrap(),
                }) as Box<dyn Process>);
            }
            let p = ScriptedProcess::new(&spec.scope_id);
            self.sessions.lock().unwrap().push(p.clone());
            if let Some(script) = self.script.lock().unwrap().take() {
                let p2 = p.clone();
                tokio::spawn(async move { script(p2).await });
            }
            Ok(Box::new(ProcessHandle(p)))
        })
    }

    fn is_alive<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<bool, Failure>> {
        Box::pin(async move {
            if let Some(e) = self.alive_err.lock().unwrap().clone() {
                return Err(e);
            }
            Ok(*self.alive.lock().unwrap().get(scope_id).unwrap_or(&false))
        })
    }

    fn kill_scope<'a>(&'a self, scope_id: &'a str) -> PortFuture<'a, Result<(), Failure>> {
        Box::pin(async move {
            self.alive.lock().unwrap().remove(scope_id);
            Ok(())
        })
    }
}

/// `launch` hands out `Box<dyn Process>`; the `Arc` inside keeps the
/// script-side handle alive.
struct ProcessHandle(Arc<ScriptedProcess>);

impl Process for ProcessHandle {
    fn scope_id(&self) -> &str {
        self.0.scope_id()
    }
    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        self.0.write_stdin(buf)
    }
    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        self.0.close_stdin()
    }
    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        self.0.read_stdout(buf)
    }
    fn read_stderr<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        self.0.read_stderr(buf)
    }
    fn wait(&self) -> PortFuture<'_, Result<ExitStatus, Failure>> {
        self.0.wait()
    }
    fn kill(&self) -> PortFuture<'_, Result<(), Failure>> {
        self.0.kill()
    }
}

/// `drain_stdin` — the script's `io.ReadAll(p.stdinR)`: attach the
/// reader and read until the adapter closes stdin. The returned task
/// ends exactly when upstream's ReadAll returns (stdin EOF or a dead
/// pipe); scripts await it before playing stdout, so the prompt write
/// always completes first.
fn drain_stdin(p: &Arc<ScriptedProcess>) -> tokio::task::JoinHandle<()> {
    let mut rx = p.take_stdin_rx();
    tokio::spawn(async move { while rx.recv().await.is_some() {} })
}

/// `scriptedSession` — drain stdin to EOF, play `stdout`, exit `code`.
fn play_stdout(stdout: Vec<u8>, code: i32) -> Script {
    Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let drained = drain_stdin(&p);
            let _ = drained.await;
            if !stdout.is_empty() {
                let _ = p.emit_raw(&stdout).await;
            }
            p.exit(ExitStatus {
                code,
                signaled: false,
            });
        })
    })
}

/// The held variant: after the fixture plays, the process stays alive
/// until `release` fires (or the adapter kills it).
fn play_held(stdout: Vec<u8>, code: i32, release: Arc<Notify>) -> Script {
    Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let drained = drain_stdin(&p);
            let _ = drained.await;
            if !stdout.is_empty() {
                let _ = p.emit_raw(&stdout).await;
            }
            release.notified().await;
            p.exit(ExitStatus {
                code,
                signaled: false,
            });
        })
    })
}

/// `run` — adapter + launcher + session.
struct Run {
    launcher: Arc<ScriptedLauncher>,
    session: Arc<dyn Session>,
}

fn new_adapter(l: Arc<dyn ProcessLauncher>) -> OpenCode {
    OpenCode::new(Config {
        launcher: Some(l),
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .unwrap()
}

async fn start_with(script: Script, spec: StartSpec) -> Run {
    let l = ScriptedLauncher::new(script);
    let a = new_adapter(l.clone());
    let s: Arc<dyn Session> = Arc::from(a.start(spec).await.expect("start"));
    Run {
        launcher: l,
        session: s,
    }
}

/// `drain` — collects every event until the stream closes, failing on
/// timeout. Every event must validate and have a strictly increasing
/// seq.
async fn collect(s: &dyn Session) -> Vec<Event> {
    let mut out = Vec::new();
    // 30 s: the oversize-frame test pushes a 16 MiB line through the
    // reader; a debug build's byte-level scan takes a few seconds.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, s.next_event())
            .await
            .expect("timed out draining events")
        {
            Some(e) => {
                e.validate().expect("invalid event");
                assert_eq!(e.seq as usize, out.len() + 1, "seq");
                out.push(e);
            }
            None => return out,
        }
    }
}

/// `terminalOf` — the LAST event must be a `TerminalReported`.
fn terminal_of(events: &[Event]) -> Terminal {
    events
        .last()
        .and_then(|e| match &e.payload {
            Some(EventPayload::TerminalReported(t)) => Some(t.terminal.clone()),
            _ => None,
        })
        .expect("last event is not TerminalReported")
}

fn exit_code(t: &Terminal) -> i32 {
    t.exit_code.unwrap_or(-1)
}

fn is_code(err: &Failure, code: &str) -> bool {
    err.code() == code
}

// =====================================================================
// opencode_test.go — identity, vocabulary, capabilities
// =====================================================================

/// `TestDefaultPinnedVersion`.
#[test]
fn default_pinned_version() {
    assert_eq!(opencode::DEFAULT_PINNED_VERSION, "1.18.32");
    let parts: Vec<&str> = opencode::DEFAULT_PINNED_VERSION.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert!(parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit())));
}

/// `TestKind`.
#[test]
fn kind_is_opencode() {
    assert_eq!(opencode::KIND, "opencode");
    central_harness::domain::Kind::new(opencode::KIND)
        .validate()
        .unwrap();
}

/// `TestReasons` — declaration order and the whole vocabulary.
#[test]
fn reasons_vocabulary() {
    let want = [
        "harness_api_error",
        "harness_exited_without_result",
        "harness_session_mismatch",
        "harness_protocol_error",
    ];
    assert_eq!(opencode::reasons(), want.as_slice());
}

/// `TestCapabilities` — the declared matrix (spec D1): `opencode run`
/// is one-shot, so only ResumeByID, UsageTokens, CostUSD (step scope).
#[test]
fn capabilities_matrix() {
    let c = opencode::capabilities();
    assert!(c.resume_by_id);
    assert!(c.usage_tokens);
    assert!(c.cost_usd);
    assert_eq!(c.usage_scope, UsageScope::Step);
    assert!(!c.streaming_input);
    assert!(!c.interrupt);
    assert!(!c.preassign_session_id);
    assert!(!c.fork);
    assert!(!c.permission_bridge);
    assert!(!c.partial_deltas);
    assert!(!c.reattach);
    assert!(!c.auto_resume_on_restart);
    assert!(!c.native_cost_limit);
    c.validate().unwrap();
}

// =====================================================================
// adapter_test.go — config, refusals, launches, reconcile
// =====================================================================

/// `TestNewValidation` — config validation (the internal field
/// assertions of the upstream test live in `src/opencode/mod.rs`'s
/// unit tests, as upstream's in-package test does).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_validates() {
    assert!(OpenCode::new(Config::default()).is_err(), "no launcher");
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    assert!(
        OpenCode::new(Config {
            launcher: Some(l.clone()),
            ..Config::default()
        })
        .is_ok()
    );
    assert!(
        OpenCode::new(Config {
            launcher: Some(l.clone()),
            pinned_version: "1.18".to_string(),
            ..Config::default()
        })
        .is_err(),
        "bad pin accepted"
    );
    assert!(
        OpenCode::new(Config {
            launcher: Some(l),
            pinned_version: "9.9.9".to_string(),
            ..Config::default()
        })
        .is_ok()
    );
}

/// `TestStartLaunchesClosedArgv` — the session argv is exactly
/// `run --format json`, the prompt travels on stdin only, and the env
/// passes through verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_launches_closed_argv() {
    let workdir = tmpdir();
    let spec = start_spec(&workdir);
    let r = start_with(play_stdout(fixture("success.ndjson"), 0), spec.clone()).await;
    let events = collect(&*r.session).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Succeeded, "{t:?}");
    let p = r.launcher.last_session();
    assert_eq!(
        String::from_utf8(p.stdin_written()).unwrap(),
        spec.prompt,
        "stdin must carry the prompt verbatim"
    );
    let launched = r.launcher.launches();
    assert_eq!(launched.len(), 2, "version probe + session");
    let sess = &launched[1];
    assert_eq!(sess.program, "opencode");
    assert_eq!(sess.work_dir, workdir);
    assert_eq!(sess.scope_id, "scope-9");
    assert_eq!(sess.args, vec!["run", "--format", "json"]);
    for arg in &sess.args {
        assert!(!arg.contains("marker-prompt"), "prompt bytes in argv");
    }
    assert_eq!(sess.env.len(), 2);
    assert_eq!(
        sess.env.get("PATH").map(String::as_str),
        Some("/usr/bin:/bin")
    );
}

/// `TestStartResumeArgv` — resume passes `--session` after `--model`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_resume_argv() {
    let workdir = tmpdir();
    let mut spec = start_spec(&workdir);
    spec.model = "opencode/mimo-v2.6-flash-free".to_string();
    let l = ScriptedLauncher::new(play_stdout(fixture("resume.ndjson"), 0));
    let a = new_adapter(l.clone());
    let s = a
        .resume(
            SessionRef {
                harness_session_id: "ses_ed9de340effe7fBtzPkP81yXKj".to_string(),
            },
            spec,
        )
        .await
        .expect("resume");
    let events = collect(&*s).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    let launched = l.launches();
    assert_eq!(launched.len(), 2);
    assert_eq!(
        launched[1].args,
        vec![
            "run",
            "--format",
            "json",
            "--model",
            "opencode/mimo-v2.6-flash-free",
            "--session",
            "ses_ed9de340effe7fBtzPkP81yXKj"
        ]
    );
}

/// `TestStartRefusesPolicyLimitsConfig` — every refusal lands before
/// any launch, with the declared code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refuses_policy_limits_config() {
    let workdir = tmpdir();

    // bridge / auto_allow — opencode supports Deny only.
    for policy in [PermissionPolicy::Bridge, PermissionPolicy::AutoAllow] {
        let l = ScriptedLauncher::unscripted();
        let a = new_adapter(l.clone());
        let mut spec = start_spec(&workdir);
        spec.permission = policy;
        let err = a
            .start(spec)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("refused"));
        assert!(
            is_code(&err, central_harness::port::codes::UNSUPPORTED),
            "{policy}: {err}"
        );
        assert!(l.launches().is_empty(), "{policy}: refused start launched");
    }

    // max turns.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut spec = start_spec(&workdir);
    spec.limits.max_turns = 5;
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(
        is_code(&err, central_harness::port::codes::UNSUPPORTED),
        "{err}"
    );

    // max cost.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut spec = start_spec(&workdir);
    spec.limits.max_cost_micro_usd = 1_000_000;
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(
        is_code(&err, central_harness::port::codes::UNSUPPORTED),
        "{err}"
    );

    // missing and misshaped resume ids.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let err = a
        .resume(SessionRef::default(), start_spec(&workdir))
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(is_code(&err, opencode::codes::INVALID_LAUNCH), "{err}");
    let err = a
        .resume(
            SessionRef {
                harness_session_id: "not-a-session".to_string(),
            },
            start_spec(&workdir),
        )
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(is_code(&err, opencode::codes::INVALID_LAUNCH), "{err}");

    // bad spec — empty prompt.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut spec = start_spec(&workdir);
    spec.prompt = String::new();
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(
        is_code(&err, central_harness::port::codes::INVALID_START_SPEC),
        "{err}"
    );

    // values never echoed.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut spec = start_spec(&workdir);
    spec.env.vars.insert(
        "FORBIDDEN_MARKER_VAR".to_string(),
        "marker-secret-value".to_string(),
    );
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(!err.message().contains("marker-secret-value"), "{err}");
}

/// `TestStartRefusesProjectConfig` — `opencode.json`, `opencode.jsonc`
/// and `.opencode` in the worktree root refuse the launch, whatever
/// their type; so do a symlink and an unreadable parent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refuses_project_config() {
    for name in ["opencode.json", "opencode.jsonc", ".opencode"] {
        let workdir = tmpdir();
        let target = std::path::Path::new(&workdir).join(name);
        if name == ".opencode" {
            std::fs::create_dir(&target).unwrap();
        } else {
            std::fs::write(&target, b"{}").unwrap();
        }
        let l = ScriptedLauncher::unscripted();
        let a = new_adapter(l.clone());
        let err = a
            .start(start_spec(&workdir))
            .await
            .err()
            .unwrap_or_else(|| unreachable!("refused"));
        assert!(
            is_code(&err, opencode::codes::INVALID_LAUNCH),
            "{name}: {err}"
        );
        assert!(err.message().contains(name), "{name}: {err}");
        assert!(l.launches().is_empty(), "{name}: refused start launched");
    }

    // A dangling symlink counts as present (Lstat, upstream).
    {
        let workdir = tmpdir();
        std::os::unix::fs::symlink(
            "elsewhere",
            std::path::Path::new(&workdir).join("opencode.json"),
        )
        .unwrap();
        let a = new_adapter(ScriptedLauncher::unscripted());
        let err = a
            .start(start_spec(&workdir))
            .await
            .err()
            .unwrap_or_else(|| unreachable!("refused"));
        assert!(is_code(&err, opencode::codes::INVALID_LAUNCH), "{err}");
    }

    // A stat error other than absence fails closed: the workspace
    // itself is a file, so every Lstat of a root entry fails ENOTDIR.
    {
        let file_dir = std::path::Path::new(&tmpdir()).join("a-file");
        std::fs::write(&file_dir, b"x").unwrap();
        let a = new_adapter(ScriptedLauncher::unscripted());
        let err = a
            .start(start_spec(&file_dir.to_string_lossy()))
            .await
            .err()
            .unwrap_or_else(|| unreachable!("refused"));
        assert!(is_code(&err, opencode::codes::INVALID_LAUNCH), "{err}");
    }
}

/// `TestStartVersionGate` — a different reported version refuses;
/// `allow_unpinned` proceeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_version_gate() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::unscripted();
    l.set_version("1.18.35\n");
    let a = new_adapter(l.clone());
    let err = a
        .start(start_spec(&workdir))
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(is_code(&err, opencode::codes::UNPINNED_VERSION), "{err}");
    assert_eq!(l.launches().len(), 1, "only the version probe may launch");

    let l = ScriptedLauncher::new(play_stdout(fixture("success.ndjson"), 0));
    l.set_version("9.9.9\n");
    let a = OpenCode::new(Config {
        launcher: Some(l),
        allow_unpinned: true,
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .unwrap();
    let s = a.start(start_spec(&workdir)).await.expect("start");
    let events = collect(&*s).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestReconcile` — reports scope liveness only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconcile_reports_scope_alive_only() {
    let l = ScriptedLauncher::unscripted();
    l.set_alive("s", true);
    let a = new_adapter(l.clone());
    let id = HarnessAttemptId::new();
    let got = a
        .reconcile(ReconcileInput {
            attempt: id,
            sandbox_scope_id: "s".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .expect("reconcile");
    assert!(got.scope_alive);
    assert!(got.reattached.is_none());
    assert!(got.terminal.is_none());

    l.set_alive("s", false);
    let got = a
        .reconcile(ReconcileInput {
            attempt: id,
            sandbox_scope_id: "s".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .expect("reconcile");
    assert!(!got.scope_alive);

    let err = a
        .reconcile(ReconcileInput {
            attempt: id,
            sandbox_scope_id: String::new(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("missing scope refused"));
    assert!(!err.message().is_empty());

    l.set_alive_err(Failure::internal("E_DOWN", "down"));
    let err = a
        .reconcile(ReconcileInput {
            attempt: id,
            sandbox_scope_id: "s".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("launcher error propagated"));
    assert_eq!(err.code(), "E_DOWN", "{err}");
}

/// `TestAdapterSurface`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adapter_surface() {
    let a = new_adapter(ScriptedLauncher::unscripted());
    assert_eq!(a.kind().as_str(), "opencode");
    assert_eq!(a.capabilities(), opencode::capabilities());
    assert!(a.env_extras().is_empty());
}

// =====================================================================
// probe_test.go
// =====================================================================

/// `TestProbe` — version parsed strictly, always authenticated, the
/// no-single-login detail, and no pin verdict on a match.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_happy() {
    let l = ScriptedLauncher::unscripted();
    l.set_version("1.18.32\n");
    let a = new_adapter(l.clone());
    let res = a.probe(probe_env()).await.expect("probe");
    assert_eq!(res.harness_version, "1.18.32");
    assert!(res.authenticated);
    assert!(
        res.detail.contains("opencode has no single login"),
        "{}",
        res.detail
    );
    assert!(
        !res.detail.contains("differs from pinned"),
        "{}",
        res.detail
    );
    let launched = l.launches();
    assert_eq!(launched.len(), 1);
    assert_eq!(launched[0].args, vec!["--version"]);
}

/// `TestProbePinVerdict` — a mismatch reports "Start refuses".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_pin_verdict() {
    let l = ScriptedLauncher::unscripted();
    l.set_version("1.18.35\n");
    let a = new_adapter(l);
    let res = a.probe(probe_env()).await.expect("probe");
    assert_eq!(res.harness_version, "1.18.35");
    assert!(res.authenticated);
    assert!(res.detail.contains("Start refuses"), "{}", res.detail);
}

/// `TestProbeRefuses` — bad shapes, nonzero exit, overlong output, a
/// missing scope, a bad PATH, a forbidden env and a launch error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_refusals() {
    for (name, out, code) in [
        ("missing patch", "1.18\n", 0),
        ("v prefix", "v1.18.32\n", 0),
        ("suffixed", "1.18.32 (opencode)\n", 0),
        ("empty", "", 0),
        ("nonzero exit", "1.18.32\n", 1),
        ("overlong output", &"1".repeat(65 << 10), 0),
    ] {
        let l = ScriptedLauncher::unscripted();
        l.set_version_out(out, code);
        let a = new_adapter(l);
        let err = a
            .probe(probe_env())
            .await
            .err()
            .unwrap_or_else(|| unreachable!("{name}: probe succeeded"));
        assert!(
            is_code(&err, opencode::codes::UNEXPECTED_PROBE_OUTPUT),
            "{name}: {err}"
        );
    }

    // missing scope.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut env = probe_env();
    env.sandbox_scope_id = String::new();
    assert!(a.probe(env).await.is_err(), "missing scope accepted");

    // bad path.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut env = probe_env();
    env.vars.insert("PATH".to_string(), "relative".to_string());
    let err = a
        .probe(env)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(is_code(&err, opencode::codes::PATH_REQUIRED), "{err}");

    // forbidden env.
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut env = probe_env();
    env.vars
        .insert("OPENCODE_CONFIG_DIR".to_string(), "/tmp/x".to_string());
    let err = a
        .probe(env)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("refused"));
    assert!(
        is_code(&err, central_harness::domain::codes::FORBIDDEN_LAUNCH_ENV),
        "{err}"
    );

    // launch error propagates.
    let l = ScriptedLauncher::unscripted();
    l.set_launch_err(Failure::internal("E_NODAEMON", "no daemon"));
    let a = new_adapter(l);
    let err = a
        .probe(probe_env())
        .await
        .err()
        .unwrap_or_else(|| unreachable!("launch error"));
    assert_eq!(err.code(), "E_NODAEMON", "{err}");
}

// =====================================================================
// session_test.go — fixtures, mapping, terminal table, kill, stdin
// =====================================================================

/// `TestSessionStartedFields` — the reveal carries the harness's own
/// id, the probed version and the configured model.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_started_fields() {
    let workdir = tmpdir();
    let mut spec = start_spec(&workdir);
    spec.model = "opencode/test-model".to_string();
    let r = start_with(play_stdout(fixture("success.ndjson"), 0), spec).await;
    let events = collect(&*r.session).await;
    match &events[0].payload {
        Some(EventPayload::SessionStarted(started)) => {
            assert_eq!(started.harness_session_id, "ses_ed9e207b5ffe63dCCCwh2SfRtm");
            assert_eq!(started.harness_version, opencode::DEFAULT_PINNED_VERSION);
            assert_eq!(started.model, "opencode/test-model");
        }
        other => unreachable!("first event = {other:?}"),
    }
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Succeeded);
    assert!(t.reason.is_empty());
    assert_eq!(exit_code(&t), 0);
    let r#ref = r.session.session_ref().await.expect("ref revealed");
    assert_eq!(r#ref.harness_session_id, "ses_ed9e207b5ffe63dCCCwh2SfRtm");
}

/// `TestToolCallResultMapping` — two tool calls map to ToolCall +
/// ToolResult pairs; inputs keep the compacted harness spelling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tool_call_result_mapping() {
    let workdir = tmpdir();
    let r = start_with(
        play_stdout(fixture("tools.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let events = collect(&*r.session).await;
    let mut calls = Vec::new();
    let mut results = Vec::new();
    let mut messages = Vec::new();
    for e in &events {
        match &e.payload {
            Some(EventPayload::ToolCall(c)) => calls.push(c.clone()),
            Some(EventPayload::ToolResult(tr)) => results.push(tr.clone()),
            Some(EventPayload::Message(m)) => messages.push(m.clone()),
            _ => {}
        }
    }
    assert_eq!(calls.len(), 2, "calls");
    assert_eq!(results.len(), 2, "results");
    assert_eq!(calls[0].name, "write");
    assert_eq!(calls[1].name, "bash");
    assert!(
        String::from_utf8_lossy(&calls[0].input).contains("/work/tooltest/hello.txt"),
        "write input = {:?}",
        calls[0].input
    );
    for tr in &results {
        assert_eq!(tr.status, ToolStatus::Ok);
    }
    assert!(
        String::from_utf8_lossy(&results[1].output).contains("HELLO-PROBE"),
        "bash output"
    );
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].role,
        central_harness::event::MessageRole::Assistant
    );
    assert!(!messages[0].partial);
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestToolErrorAndDeniedMapping` — a tool error is `error`; the exact
/// auto-reject text is `denied`, both carrying the error text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tool_error_and_denied_mapping() {
    for (name, status, output) in [
        (
            "tool-error.ndjson",
            ToolStatus::Error,
            "File not found: /work/definitely-not-here-xyz.txt",
        ),
        (
            "denied-tool.ndjson",
            ToolStatus::Denied,
            "The user rejected permission to use this specific tool call.",
        ),
    ] {
        let workdir = tmpdir();
        let r = start_with(play_stdout(fixture(name), 0), start_spec(&workdir)).await;
        let events = collect(&*r.session).await;
        let results: Vec<_> = events
            .iter()
            .filter_map(|e| match &e.payload {
                Some(EventPayload::ToolResult(tr)) => Some(tr.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(results.len(), 1, "{name}");
        assert_eq!(results[0].status, status, "{name}");
        assert_eq!(
            String::from_utf8_lossy(&results[0].output),
            output,
            "{name}"
        );
        assert_eq!(
            terminal_of(&events).status,
            TerminalStatus::Succeeded,
            "{name}"
        );
    }
}

/// `TestUsageReports` — the step-finish becomes a per-step report with
/// reasoning folded into the output counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn usage_reports() {
    let workdir = tmpdir();
    let r = start_with(
        play_stdout(fixture("success.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let events = collect(&*r.session).await;
    let reports: Vec<Usage> = events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::UsageReport(u)) => Some(u.usage),
            _ => None,
        })
        .collect();
    assert_eq!(reports.len(), 1, "reports");
    let want = Usage {
        tokens_in: 84755,
        tokens_out: 11,
        cache_read: 3520,
        cache_write: 0,
        cost_micro_usd: 0,
        scope: UsageScope::Step,
        estimated: false,
    };
    assert_eq!(reports[0], want);
}

/// `TestUnknownTypeWarnsAndContinues` — an unrecognized envelope type
/// warns once and the stream continues.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_type_warns_and_continues() {
    let workdir = tmpdir();
    let r = start_with(
        play_stdout(fixture("unknown-type.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let events = collect(&*r.session).await;
    let mut warnings = 0;
    let mut saw_message = false;
    let mut raw = Vec::new();
    for e in &events {
        match &e.payload {
            Some(EventPayload::Warning(w)) => {
                warnings += 1;
                assert_eq!(w.message, "unrecognized harness message");
                raw = e.raw.clone();
            }
            Some(EventPayload::Message(_)) => saw_message = true,
            _ => {}
        }
    }
    assert_eq!(warnings, 1);
    assert!(saw_message);
    assert!(String::from_utf8_lossy(&raw).contains("future_widget"));
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestReasoningSkippedSilently` — reasoning parts are structural:
/// no Reasoning event, no warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reasoning_skipped_silently() {
    let workdir = tmpdir();
    let r = start_with(
        play_stdout(fixture("reasoning.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let events = collect(&*r.session).await;
    for e in &events {
        assert!(
            !matches!(
                &e.payload,
                Some(EventPayload::Reasoning(_)) | Some(EventPayload::Warning(_))
            ),
            "unexpected payload: {:?}",
            e.payload
        );
    }
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestMalformedLinesWarnAndContinue` — every malformed line warns
/// and the session continues to the next good frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_lines_warn_and_continue() {
    let lines: Vec<&str> = vec![
        "not json",
        r#"{"type":"","sessionID":"ses_x"}"#,
        r#"{"type":"text","part":{"type":"text","text":"noid"}}"#,
        r#"{"type":"text","sessionID":"ses_ok","part":{"type":"text","text":42}}"#,
        r#"{"type":"tool_use","sessionID":"ses_ok","part":{"type":"tool"}}"#,
        r#"{"type":"step_finish","sessionID":"ses_ok","part":{"type":"step-finish","tokens":{"input":1.5}}}"#,
        r#"{"type":"step_start","timestamp":1,"sessionID":"ses_ok","part":{"id":"p","messageID":"m","sessionID":"ses_ok","type":"step-start"}}"#,
        r#"{"type":"text","timestamp":2,"sessionID":"ses_ok","part":{"id":"p","messageID":"m","sessionID":"ses_ok","type":"text","text":"fine","time":{"start":1,"end":2}}}"#,
    ];
    let mut stdout = lines.join("\n");
    stdout.push('\n');
    let workdir = tmpdir();
    let r = start_with(play_stdout(stdout.into_bytes(), 0), start_spec(&workdir)).await;
    let events = collect(&*r.session).await;
    let mut warnings = 0;
    let mut saw_message = false;
    for e in &events {
        match &e.payload {
            Some(EventPayload::Warning(w)) => {
                warnings += 1;
                assert_eq!(w.message, "malformed harness frame");
            }
            Some(EventPayload::Message(m)) if m.text == "fine" => saw_message = true,
            _ => {}
        }
    }
    assert_eq!(warnings, 6, "warnings");
    assert!(saw_message);
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestResumeMismatchStops` — a resumed session reporting a different
/// id is killed and fails closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_mismatch_stops() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_stdout(fixture("success.ndjson"), 0));
    let a = new_adapter(l.clone());
    let s = a
        .resume(
            SessionRef {
                harness_session_id: "ses_expected00000000000001".to_string(),
            },
            start_spec(&workdir),
        )
        .await
        .expect("resume");
    let events = collect(&*s).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, opencode::reasons::HARNESS_SESSION_MISMATCH);
    let p = l.last_session();
    assert!(p.kill_count() >= 1, "mismatched session was not killed");
    assert!(
        s.session_ref().await.is_none(),
        "ref resolved on a mismatched session"
    );
}

/// `TestMidstreamMismatchStops` — a session id change mid-stream
/// fails closed; nothing from the wrong session is emitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn midstream_mismatch_stops() {
    let lines = [
        r#"{"type":"step_start","timestamp":1,"sessionID":"ses_first000000000000001","part":{"id":"p","messageID":"m","sessionID":"ses_first000000000000001","type":"step-start"}}"#,
        r#"{"type":"text","timestamp":2,"sessionID":"ses_other000000000000002","part":{"id":"p","messageID":"m","sessionID":"ses_other000000000000002","type":"text","text":"hijack","time":{"start":1,"end":2}}}"#,
    ];
    let stdout = format!("{}\n", lines.join("\n"));
    let workdir = tmpdir();
    let r = start_with(play_stdout(stdout.into_bytes(), 0), start_spec(&workdir)).await;
    let events = collect(&*r.session).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, opencode::reasons::HARNESS_SESSION_MISMATCH);
    for e in &events {
        assert!(
            !matches!(&e.payload, Some(EventPayload::Message(_))),
            "mismatched frame reached the stream"
        );
    }
}

/// `TestOversizeLineStops` — a frame past the cap fails closed with
/// the protocol reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_line_stops() {
    let big = format!(
        "{}{}{}{}",
        r#"{"type":"text","sessionID":"ses_big","part":{"type":"text","text":""#,
        "x".repeat(16 << 20),
        r#""}}"#,
        "\n"
    );
    let workdir = tmpdir();
    let r = start_with(play_stdout(big.into_bytes(), 0), start_spec(&workdir)).await;
    let events = collect(&*r.session).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, opencode::reasons::HARNESS_PROTOCOL_ERROR);
}

/// `TestTerminalTable` — the terminal-status mapping rows: an error
/// envelope fails with the api reason even on exit 0, an empty stream
/// takes the exit code's verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_table() {
    struct Case {
        name: &'static str,
        fixture: &'static str,
        inline: &'static str,
        code: i32,
        status: TerminalStatus,
        reason: &'static str,
    }
    let cases = [
        Case {
            name: "api error",
            fixture: "api-error.ndjson",
            inline: "",
            code: 1,
            status: TerminalStatus::Failed,
            reason: "harness_api_error",
        },
        Case {
            name: "bad model",
            fixture: "bad-model.ndjson",
            inline: "",
            code: 1,
            status: TerminalStatus::Failed,
            reason: "harness_api_error",
        },
        Case {
            name: "empty exit 1",
            fixture: "unknown-session-empty.ndjson",
            inline: "",
            code: 1,
            status: TerminalStatus::Failed,
            reason: "harness_exited_without_result",
        },
        Case {
            name: "empty exit 0",
            fixture: "unknown-session-empty.ndjson",
            inline: "",
            code: 0,
            status: TerminalStatus::Succeeded,
            reason: "",
        },
        Case {
            name: "resume ok",
            fixture: "resume.ndjson",
            inline: "",
            code: 0,
            status: TerminalStatus::Succeeded,
            reason: "",
        },
        Case {
            name: "error event with exit 0 still fails",
            fixture: "",
            inline: "{\"type\":\"error\",\"timestamp\":1,\"sessionID\":\"ses_e\",\"error\":{\"name\":\"X\"}}\n",
            code: 0,
            status: TerminalStatus::Failed,
            reason: "harness_api_error",
        },
    ];
    for tc in cases {
        let stdout = if tc.fixture.is_empty() {
            tc.inline.as_bytes().to_vec()
        } else {
            fixture(tc.fixture)
        };
        let workdir = tmpdir();
        let r = start_with(play_stdout(stdout, tc.code), start_spec(&workdir)).await;
        let events = collect(&*r.session).await;
        let t = terminal_of(&events);
        assert_eq!(t.status, tc.status, "{}: {t:?}", tc.name);
        assert_eq!(t.reason, tc.reason, "{}: {t:?}", tc.name);
        assert_eq!(exit_code(&t), tc.code, "{}: {t:?}", tc.name);
        assert!(
            tc.reason.is_empty() || opencode::reasons().contains(&tc.reason),
            "{}: reason outside the vocabulary",
            tc.name
        );
        for e in &events {
            assert!(!e.raw.is_empty(), "{}: event with empty raw", tc.name);
        }
    }
}

/// `TestKillEndsKilled` — kill before the end reports Killed and the
/// same terminal through `wait`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_ends_killed() {
    let release = Arc::new(Notify::new());
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_held(Vec::new(), 0, release.clone()));
    let a = new_adapter(l);
    let s = a.start(start_spec(&workdir)).await.expect("start");
    s.kill().await.expect("kill");
    release.notify_one();
    let events = collect(&*s).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Killed);
    assert!(t.reason.is_empty());
    let t2 = s.wait().await.expect("wait");
    assert_eq!(t2.status, TerminalStatus::Killed);
}

/// `TestInterruptSendRespond` — Send and Interrupt are unsupported on
/// the live session (Interrupt reports SESSION_ENDED once finished);
/// RespondPermission never has a pending request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupt_send_respond() {
    let release = Arc::new(Notify::new());
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_held(fixture("success.ndjson"), 0, release.clone()));
    let a = new_adapter(l);
    let s = a.start(start_spec(&workdir)).await.expect("start");

    // Give the fixture time to be emitted and consumed; the process is
    // held, so the session is live.
    let err = s
        .interrupt()
        .await
        .err()
        .unwrap_or_else(|| unreachable!("interrupt refused"));
    assert!(
        is_code(&err, central_harness::port::codes::UNSUPPORTED),
        "{err}"
    );
    let err = s
        .send(OperatorInput {
            text: "hi".to_string(),
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("send refused"));
    assert!(
        is_code(&err, central_harness::port::codes::UNSUPPORTED),
        "{err}"
    );
    let err = s
        .respond_permission(PermissionDecision {
            request_id: "r".to_string(),
            allow: false,
            option_id: String::new(),
            decided_by: "t".to_string(),
            input_sha256: [0; 32],
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("respond refused"));
    assert!(
        is_code(&err, central_harness::port::codes::NO_PENDING_PERMISSION),
        "{err}"
    );

    release.notify_one();
    let events = collect(&*s).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    let err = s
        .interrupt()
        .await
        .err()
        .unwrap_or_else(|| unreachable!("interrupt refused"));
    assert!(
        is_code(&err, central_harness::port::codes::SESSION_ENDED),
        "{err}"
    );
    let err = s
        .respond_permission(PermissionDecision {
            request_id: "r".to_string(),
            allow: false,
            option_id: String::new(),
            decided_by: "t".to_string(),
            input_sha256: [0; 32],
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("respond refused"));
    assert!(
        is_code(&err, central_harness::port::codes::NO_PENDING_PERMISSION),
        "{err}"
    );
}

/// `TestStdinDelivery` — a large prompt travels to stdin verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_delivery() {
    let prompt = "p".repeat(1 << 20);
    let workdir = tmpdir();
    let mut spec = start_spec(&workdir);
    spec.prompt = prompt.clone();
    let r = start_with(play_stdout(fixture("success.ndjson"), 0), spec).await;
    let events = collect(&*r.session).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    let p = r.launcher.last_session();
    assert_eq!(p.stdin_written().len(), prompt.len(), "stdin byte count");
    assert_eq!(p.stdin_written(), prompt.as_bytes());
}

/// `TestFixtureHygiene` — no secrets markers, sane sizes, every line
/// is JSON.
#[test]
fn fixture_hygiene() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/opencode");
    let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert!(!entries.is_empty(), "no fixtures");
    let markers = [
        "apikey",
        "api_key",
        "cf-ray",
        "request id",
        "request_id",
        "secret",
        "passwd",
        "bearer",
        "authorization",
        "begin ",
    ];
    for e in entries {
        let e = e.unwrap();
        let raw = std::fs::read(e.path()).unwrap();
        assert!(
            raw.len() <= 100 << 10,
            "{} is {} bytes, want < 100 KiB",
            e.file_name().to_string_lossy(),
            raw.len()
        );
        let lowered = String::from_utf8_lossy(&raw).to_lowercase();
        for m in markers {
            assert!(
                !lowered.contains(m),
                "{} contains marker {m:?}",
                e.file_name().to_string_lossy()
            );
        }
        for line in String::from_utf8_lossy(&raw).split('\n') {
            if line.is_empty() {
                continue;
            }
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "{} has a non-JSON line: {line}",
                e.file_name().to_string_lossy()
            );
        }
    }
}

/// `TestStdinDeliveryFailureWarns` — the child exits before reading
/// stdin: the prompt write fails, the session warns once, and the
/// terminal still comes from the exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_delivery_failure_warns() {
    let workdir = tmpdir();
    let mut spec = start_spec(&workdir);
    spec.prompt = "p".repeat(1 << 20);
    let l = ScriptedLauncher::new(Box::new(|p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            p.exit(ExitStatus {
                code: 1,
                signaled: false,
            });
        })
    }));
    let a = new_adapter(l);
    let s = a.start(spec).await.expect("start");
    let events = collect(&*s).await;
    let warnings: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::Warning(w)) => Some(w.message.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(warnings, vec!["delivering the prompt failed".to_string()]);
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, opencode::reasons::HARNESS_EXITED_WITHOUT_RESULT);
}
