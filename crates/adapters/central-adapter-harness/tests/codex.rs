//! `adapter_test.go` + `probe_test.go` + `session_test.go` + the
//! identity half of `codex_test.go` — the scripted fake-harness tests
//! over the verbatim `testdata/` fixtures. A `ScriptedLauncher`
//! answers the `--version` and `login status` probes with fixed
//! output and hands every session launch to a scripted in-memory
//! `Process`; the play helpers replay fixture bytes exactly as
//! upstream's `scriptedSession` does.

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

use central_adapter_harness::codex::{self, Codex, Config};
use central_foundation::failure::Failure;
use central_foundation::identity::HarnessAttemptId;
use central_harness::domain::{Fence, PermissionPolicy, Terminal, TerminalStatus, Workspace};
use central_harness::event::{Event, EventPayload, ToolStatus, UsageScope};
use central_harness::port::{
    Adapter as _, ExitStatus, LaunchEnv, OperatorInput, PermissionDecision, PortFuture, Process,
    ProcessLauncher, ProcessSpec, ReconcileInput, Session, SessionRef, StartSpec,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

const THREAD_ID: &str = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/codex")
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
        env: probe_env(),
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
        "central-codex-test-{}-{}",
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
/// stdin, and exits with a status.
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
            stderr: Mutex::new(b"rollout diagnostics never mapped to reason\n".to_vec()),
            exited: Notify::new(),
            status: Mutex::new(None),
            kills: AtomicUsize::new(0),
        })
    }

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
        self.stdin_tx.lock().unwrap().take();
        self.stdin_dead.store(true, Ordering::SeqCst);
        self.stdin_gate.notify_waiters();
        self.exited.notify_waiters();
    }

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

/// `scriptedLauncher` — fixed probe output for `--version` and
/// `login status`; session launches go to a harness script.
struct ScriptedLauncher {
    launches: Mutex<Vec<ProcessSpec>>,
    version: Mutex<String>,
    version_code: Mutex<i32>,
    login_code: Mutex<i32>,
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
            version: Mutex::new("codex-cli 0.162.1\n".to_string()),
            version_code: Mutex::new(0),
            login_code: Mutex::new(0),
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

    fn set_version_out(&self, out: &str, code: i32) {
        *self.version.lock().unwrap() = out.to_string();
        *self.version_code.lock().unwrap() = code;
    }

    fn set_login_code(&self, code: i32) {
        *self.login_code.lock().unwrap() = code;
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
            if spec.args.as_slice() == ["login", "status"] {
                // Output is drained and discarded upstream (spec S9):
                // a masked key must never be parsed or recorded.
                return Ok(Box::new(StaticProcess {
                    scope: spec.scope_id.clone(),
                    stdout: Mutex::new(b"Logged in using API key (sk-***)\n".to_vec()),
                    stderr: Mutex::new(Vec::new()),
                    code: *self.login_code.lock().unwrap(),
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
/// reader and read until the adapter closes stdin.
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

fn new_adapter(l: Arc<dyn ProcessLauncher>) -> Codex {
    Codex::new(Config {
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

fn is_code(err: &Failure, code: &str) -> bool {
    err.code() == code
}

fn warning_messages(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::Warning(w)) => Some(w.message.clone()),
            _ => None,
        })
        .collect()
}

// =====================================================================
// codex_test.go — identity, vocabulary, capabilities
// =====================================================================

/// `TestDefaultPinnedVersion`.
#[test]
fn default_pinned_version() {
    assert_eq!(codex::DEFAULT_PINNED_VERSION, "0.162.1");
}

/// `TestKind`.
#[test]
fn kind_is_codex() {
    assert_eq!(codex::KIND, "codex");
    central_harness::domain::Kind::new(codex::KIND)
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
    assert_eq!(codex::reasons(), want.as_slice());
}

/// `TestCapabilities` — `codex exec` is one-shot: ResumeByID and
/// UsageTokens (session-cumulative) only; no cost, no bridge.
#[test]
fn capabilities_matrix() {
    let c = codex::capabilities();
    assert!(c.resume_by_id);
    assert!(c.usage_tokens);
    assert_eq!(c.usage_scope, UsageScope::SessionCumulative);
    assert!(!c.cost_usd);
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

/// `TestNewValidation`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_validates() {
    assert!(Codex::new(Config::default()).is_err(), "no launcher");
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    assert!(
        Codex::new(Config {
            launcher: Some(l.clone()),
            ..Config::default()
        })
        .is_ok()
    );
    assert!(
        Codex::new(Config {
            launcher: Some(l.clone()),
            pinned_version: "0.162".to_string(),
            ..Config::default()
        })
        .is_err(),
        "bad pin accepted"
    );
    assert!(
        Codex::new(Config {
            launcher: Some(l),
            pinned_version: "9.9.9".to_string(),
            ..Config::default()
        })
        .is_ok()
    );
}

/// `TestStartLaunchesClosedArgv` — the session argv is exactly
/// `exec --json -s workspace-write -`, the prompt travels on stdin
/// only, and the env passes through verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_launches_closed_argv() {
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("success.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let launches = run.launcher.launches();
    // launches[0] is the --version probe; the session is last.
    let session_spec = launches.last().unwrap();
    assert_eq!(
        session_spec.args,
        ["exec", "--json", "-s", "workspace-write", "-"]
    );
    assert_eq!(session_spec.program, "codex");
    assert_eq!(session_spec.work_dir, workdir);
    assert_eq!(session_spec.scope_id, "probe-scope");
    assert_eq!(
        session_spec.env.get("PATH").map(String::as_str),
        Some("/usr/bin:/bin")
    );
    assert!(
        !session_spec
            .args
            .iter()
            .any(|a| a.contains("marker-prompt")),
        "prompt must never appear in argv"
    );
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    // The prompt went over stdin.
    let p = run.launcher.last_session();
    assert_eq!(
        p.stdin_written(),
        b"marker-prompt- Run the Bash command: echo probe"
    );
}

/// `TestStartResumeArgv` — `exec resume --json -c
/// sandbox_mode="workspace-write" [--model M] <uuid> -`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_resume_argv() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_stdout(fixture("resume.ndjson"), 0));
    let a = new_adapter(l.clone());
    let mut spec = start_spec(&workdir);
    spec.model = "gpt-5.3-codex".to_string();
    let s: Arc<dyn Session> = Arc::from(
        a.resume(
            SessionRef {
                harness_session_id: "dddddddd-dddd-4ddd-dddd-dddddddddddd".to_string(),
            },
            spec,
        )
        .await
        .expect("resume"),
    );
    let ev = collect(&*s).await;
    let session_spec = l.launches().last().unwrap().clone();
    assert_eq!(
        session_spec.args,
        [
            "exec",
            "resume",
            "--json",
            "-c",
            "sandbox_mode=\"workspace-write\"",
            "--model",
            "gpt-5.3-codex",
            "dddddddd-dddd-4ddd-dddd-dddddddddddd",
            "-"
        ]
    );
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
}

/// `TestStartRefusesPolicyLimitsConfig` — deny-only, no max-turns, no
/// native cost limit; malformed resume ids and bad specs refuse too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refuses_policy_limits_config() {
    let workdir = tmpdir();
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    for (name, mutate) in [
        (
            "permission bridge",
            Box::new(|s: &mut StartSpec| s.permission = PermissionPolicy::Bridge)
                as Box<dyn FnOnce(&mut StartSpec)>,
        ),
        (
            "permission auto",
            Box::new(|s: &mut StartSpec| s.permission = PermissionPolicy::AutoAllow)
                as Box<dyn FnOnce(&mut StartSpec)>,
        ),
        (
            "max turns",
            Box::new(|s: &mut StartSpec| s.limits.max_turns = 3) as Box<dyn FnOnce(&mut StartSpec)>,
        ),
        (
            "max cost",
            Box::new(|s: &mut StartSpec| s.limits.max_cost_micro_usd = 500)
                as Box<dyn FnOnce(&mut StartSpec)>,
        ),
    ] {
        let mut spec = start_spec(&workdir);
        mutate(&mut spec);
        let err = a
            .start(spec)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("expected refusal"));
        assert!(
            is_code(&err, central_harness::port::codes::UNSUPPORTED),
            "{name}: {err:?}"
        );
    }
    // Missing PATH refuses.
    let mut spec = start_spec(&workdir);
    spec.env.vars.remove("PATH");
    assert!(is_code(
        &a.start(spec)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("expected refusal")),
        codex::codes::PATH_REQUIRED
    ));
    // A relative PATH entry refuses without echoing the value.
    let mut spec = start_spec(&workdir);
    spec.env
        .vars
        .insert("PATH".to_string(), "rel/bin".to_string());
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(&err, codex::codes::PATH_REQUIRED));
    assert!(!err.message().contains("rel/bin"));
    // Bad resume ids refuse before launch.
    for bad in ["", "abc123", "BBBBBBBB-BBBB-4BBB-BBBB-BBBBBBBBBBBB"] {
        let err = a
            .resume(
                SessionRef {
                    harness_session_id: bad.to_string(),
                },
                start_spec(&workdir),
            )
            .await
            .err()
            .unwrap_or_else(|| unreachable!("expected refusal"));
        assert!(is_code(&err, codex::codes::INVALID_LAUNCH), "{bad}");
    }
}

/// `TestStartRefusesProjectConfig` — a `.codex` entry in the worktree
/// refuses the launch fail-closed, whatever its file type.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refuses_project_config() {
    // A directory named .codex refuses.
    let workdir = tmpdir();
    std::fs::create_dir(std::path::Path::new(&workdir).join(".codex")).unwrap();
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    let err = a
        .start(start_spec(&workdir))
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(&err, codex::codes::INVALID_LAUNCH));
    // A plain file refuses too.
    let workdir = tmpdir();
    std::fs::write(std::path::Path::new(&workdir).join(".codex"), b"x").unwrap();
    let err = a
        .start(start_spec(&workdir))
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(&err, codex::codes::INVALID_LAUNCH));
    // No .codex: launches fine.
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_stdout(fixture("success.ndjson"), 0));
    let a = new_adapter(l);
    assert!(a.start(start_spec(&workdir)).await.is_ok());
}

/// `TestStartVersionGate` — a differing version refuses unless
/// `AllowUnpinned`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_version_gate() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_stdout(fixture("success.ndjson"), 0));
    l.set_version_out("codex-cli 9.9.9\n", 0);
    let a = new_adapter(l.clone());
    let err = a
        .start(start_spec(&workdir))
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(&err, codex::codes::UNPINNED_VERSION));
    assert!(err.message().contains("9.9.9"));
    assert!(err.message().contains("0.162.1"));
    // AllowUnpinned launches.
    let a = Codex::new(Config {
        launcher: Some(l),
        allow_unpinned: true,
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .unwrap();
    let s = a.start(start_spec(&workdir)).await.expect("start unpinned");
    let ev = collect(&*s).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
}

/// `TestReconcile` — reports scope liveness only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconcile_scope_alive() {
    let l = ScriptedLauncher::unscripted();
    l.set_alive("scope-9", true);
    let a = new_adapter(l.clone());
    let r = a
        .reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: "scope-9".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .unwrap();
    assert!(r.scope_alive);
    let r = a
        .reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: "other".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .unwrap();
    assert!(!r.scope_alive);
    l.set_alive_err(Failure::internal("E_UP", "alive broke"));
    assert!(
        a.reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: "scope-9".to_string(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .is_err()
    );
    assert!(
        a.reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: String::new(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .is_err()
    );
}

/// `TestAdapterSurface` — kind, capabilities, env extras.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adapter_surface() {
    let l: Arc<dyn ProcessLauncher> = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    assert_eq!(a.kind().as_str(), "codex");
    assert!(a.env_extras().is_empty());
    assert!(a.capabilities().resume_by_id);
}

// =====================================================================
// probe_test.go — the version and login probes
// =====================================================================

/// `TestProbe` — both probe commands run through the launcher in the
/// probe workdir; the result reports version + auth.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_reports_version_and_auth() {
    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l.clone());
    let r = a.probe(probe_env()).await.unwrap();
    assert_eq!(r.harness_version, "0.162.1");
    assert!(r.authenticated);
    assert!(r.detail.contains("login status"));
    let launches = l.launches();
    assert_eq!(launches.len(), 2);
    assert_eq!(launches[0].args, ["--version"]);
    assert_eq!(launches[1].args, ["login", "status"]);
    assert!(launches.iter().all(|s| s.work_dir == "/probe"));
    assert!(launches.iter().all(|s| s.scope_id == "probe-scope"));
}

/// `TestProbeLoginStatus` — the login exit code alone decides
/// `authenticated`; its output is never parsed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_login_status() {
    for (code, want) in [(0, true), (1, false), (3, false)] {
        let l = ScriptedLauncher::unscripted();
        l.set_login_code(code);
        let a = new_adapter(l);
        let r = a.probe(probe_env()).await.unwrap();
        assert_eq!(r.authenticated, want, "code {code}");
        assert_eq!(r.harness_version, "0.162.1");
    }
}

/// `TestProbePinVerdict` — the probe reports but never gates on the
/// version; detail records the pin verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_pin_verdict() {
    let l = ScriptedLauncher::unscripted();
    l.set_version_out("codex-cli 0.163.0\n", 0);
    let a = new_adapter(l.clone());
    let r = a.probe(probe_env()).await.unwrap();
    assert_eq!(r.harness_version, "0.163.0");
    assert!(r.detail.contains("differs from pinned"));
    assert!(r.detail.contains("Start refuses"));
    let a = Codex::new(Config {
        launcher: Some(l),
        allow_unpinned: true,
        ..Config::default()
    })
    .unwrap();
    let r = a.probe(probe_env()).await.unwrap();
    assert!(r.detail.contains("allowed by AllowUnpinned"));
}

/// `TestProbeRefuses` — every failure mode refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_refuses() {
    for (name, out, code) in [
        ("missing patch", "codex-cli 0.162\n", 0),
        ("suffixed", "codex-cli 0.162.1 (codex)\n", 0),
        ("nonzero exit", "codex-cli 0.162.1\n", 1),
        ("garbage", "garbage", 0),
        ("empty", "", 0),
    ] {
        let l = ScriptedLauncher::unscripted();
        l.set_version_out(out, code);
        let a = new_adapter(l);
        let err = a
            .probe(probe_env())
            .await
            .err()
            .unwrap_or_else(|| unreachable!("expected refusal"));
        assert!(
            is_code(&err, codex::codes::UNEXPECTED_PROBE_OUTPUT),
            "{name}: {err:?}"
        );
        assert!(
            !err.message().contains("0.162.1") || name == "nonzero exit",
            "{name}: output leaked"
        );
    }
    // Missing scope refuses.
    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    let mut env = probe_env();
    env.sandbox_scope_id.clear();
    assert!(a.probe(env).await.is_err());
    // Missing PATH refuses.
    let mut env = probe_env();
    env.vars.remove("PATH");
    assert!(is_code(
        &a.probe(env)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("expected refusal")),
        codex::codes::PATH_REQUIRED
    ));
    // A forbidden env var refuses.
    let mut env = probe_env();
    env.vars
        .insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
    assert!(a.probe(env).await.is_err());
    // Launch failure surfaces.
    let l = ScriptedLauncher::unscripted();
    l.set_launch_err(Failure::internal("E_UP", "launcher down"));
    let a = new_adapter(l);
    assert!(a.probe(probe_env()).await.is_err());
}

// =====================================================================
// session_test.go — the event-mapping and lifecycle tests
// =====================================================================

/// `TestSessionStartedFields` — success.ndjson: reveal, message,
/// cumulative usage, success terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_started_fields() {
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("success.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let r = run.session.session_ref().await.expect("session ref");
    assert_eq!(r.harness_session_id, THREAD_ID);
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    match &ev[0].payload {
        Some(EventPayload::SessionStarted(s)) => {
            assert_eq!(s.harness_session_id, THREAD_ID);
            assert_eq!(s.harness_version, "0.162.1");
            assert!(s.model.is_empty());
        }
        p => unreachable!("first event: {p:?}"),
    }
    let msgs: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::Message(m)) => Some(m.text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(msgs, ["ok"]);
    let usage: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::UsageReport(u)) => Some(u.usage),
            _ => None,
        })
        .collect();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].tokens_in, 120);
    assert_eq!(usage[0].tokens_out, 40, "30 + 10 reasoning folded");
    assert_eq!(usage[0].cache_read, 40);
    assert_eq!(usage[0].cache_write, 5);
    assert_eq!(usage[0].scope, UsageScope::SessionCumulative);
    // Every event carries the harness session id once revealed.
    assert!(ev.iter().all(|e| e.harness_session_id == THREAD_ID));
}

/// `TestToolPairing` — command.ndjson: started command_execution
/// pairs with its completed result; aggregated_output is the output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tool_pairing() {
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("command.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let calls: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolCall(c)) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].id, "item_0");
    assert_eq!(calls[0].name, "command_execution");
    assert_eq!(calls[0].input, b"cat hello.txt".to_vec());
    let results: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolResult(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "item_0");
    assert_eq!(results[0].status, ToolStatus::Ok);
    assert_eq!(results[0].output, b"HELLO-PROBE".to_vec());
    assert!(warning_messages(&ev).is_empty());
}

/// `TestToolErrorDeniedAndSynthesis` — failed/declined statuses map,
/// and a completed-only file_change synthesizes its ToolCall.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tool_error_denied_and_synthesis() {
    for (fixture_name, want_status, want_out) in [
        (
            "command-failed.ndjson",
            ToolStatus::Error,
            "cat: missing.txt: No such file or directory",
        ),
        ("command-declined.ndjson", ToolStatus::Denied, ""),
    ] {
        let workdir = tmpdir();
        let run = start_with(play_stdout(fixture(fixture_name), 0), start_spec(&workdir)).await;
        let ev = collect(&*run.session).await;
        assert_eq!(
            terminal_of(&ev).status,
            TerminalStatus::Succeeded,
            "{fixture_name}"
        );
        let results: Vec<_> = ev
            .iter()
            .filter_map(|e| match &e.payload {
                Some(EventPayload::ToolResult(r)) => Some(r.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(results.len(), 1, "{fixture_name}");
        assert_eq!(results[0].status, want_status, "{fixture_name}");
        assert_eq!(
            results[0].output,
            want_out.as_bytes().to_vec(),
            "{fixture_name}"
        );
    }
    // file_change arrives completed-only → synthesized ToolCall +
    // raw-status output.
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("file-change.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let calls: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolCall(c)) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name, "file_change");
    assert_eq!(
        calls[0].input,
        br#"[{"path":"/work/hello.txt","kind":"add"}]"#.to_vec()
    );
    let results: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolResult(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(results[0].output, b"completed".to_vec());
}

/// `TestMCPWebCollabMapping` — the three structured tool types map to
/// their discriminating fields.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mcp_web_collab_mapping() {
    // mcp: arguments compacted as input, result compacted as output.
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("mcp-call.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let calls: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolCall(c)) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls[0].name, "mcp_tool_call");
    assert_eq!(calls[0].input, br#"{"q":"codex"}"#.to_vec());
    let results: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolResult(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        results[0].output,
        br#"{"content":[{"type":"text","text":"docs"}]}"#.to_vec()
    );
    // web_search: query input, results output, no status member.
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("web-search.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let calls: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolCall(c)) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls[0].name, "web_search");
    assert_eq!(calls[0].input, b"codex exec json".to_vec());
    let results: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolResult(r)) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        results[0].output,
        br#"[{"url":"https://example.invalid/docs"}]"#.to_vec()
    );
    // collab: absent prompt → empty input; agents_states output.
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("collab-call.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let calls: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::ToolCall(c)) => Some(c.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(calls[0].name, "collab_tool_call");
    assert!(calls[0].input.is_empty());
}

/// `TestReasoningTodoSkippedSilently` — reasoning, todo_list and
/// item.updated emit nothing, no warnings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reasoning_todo_skipped_silently() {
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("reasoning-todo-skip.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    assert!(warning_messages(&ev).is_empty());
    let msgs: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::Message(m)) => Some(m.text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(msgs, ["Done."]);
    assert_eq!(ev.len(), 4, "SessionStarted + Message + Usage + Terminal");
}

/// `TestErrorItemsWarnAndSkip` — error items and top-level errors warn
/// "codex non-fatal error" and never turn terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_items_warn_and_skip() {
    for fixture_name in ["error-item.ndjson", "top-error.ndjson"] {
        let workdir = tmpdir();
        let run = start_with(play_stdout(fixture(fixture_name), 0), start_spec(&workdir)).await;
        let ev = collect(&*run.session).await;
        assert_eq!(
            terminal_of(&ev).status,
            TerminalStatus::Succeeded,
            "{fixture_name}"
        );
        let warns = warning_messages(&ev);
        assert_eq!(warns, ["codex non-fatal error"], "{fixture_name}");
    }
    // auth-failure: the retry notices warn non-fatally; the terminal
    // turn.failed ends as api_error.
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("auth-failure.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_api_error");
    let warns = warning_messages(&ev);
    assert!(
        warns.iter().all(|w| w == "codex non-fatal error"),
        "{warns:?}"
    );
    assert_eq!(warns.len(), 11, "10 top errors + 1 error item");
}

/// `TestUnknownTypeWarnsAndContinues` — an unrecognized frame warns
/// "unrecognized harness message" and processing continues.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_type_warns_and_continues() {
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("unknown-type.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    assert_eq!(warning_messages(&ev), ["unrecognized harness message"]);
}

/// `TestMalformedLinesWarnAndContinue`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_lines_warn_and_continue() {
    let mut stream = Vec::new();
    stream.extend_from_slice(b"not json\n");
    stream.extend_from_slice(
        format!("{{\"type\":\"thread.started\",\"thread_id\":\"{THREAD_ID}\"}}\n").as_bytes(),
    );
    stream.extend_from_slice(b"{\"type\":123}\n");
    stream.extend_from_slice(
        b"{\"type\":\"item.completed\",\"item\":{\"id\":\"i\",\"type\":\"agent_message\",\"text\":\"t\"}}\n",
    );
    stream.extend_from_slice(b"{\"type\":\"thread.started\"}\n");
    let workdir = tmpdir();
    let run = start_with(play_stdout(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let warns = warning_messages(&ev);
    assert_eq!(
        warns,
        [
            "malformed harness frame",
            "malformed harness frame",
            "malformed harness frame"
        ]
    );
    let msgs: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::Message(m)) => Some(m.text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(msgs, ["t"]);
}

/// `TestStartedAgentMessageWarns` — a started non-tool non-todo item
/// warns "unrecognized codex item".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn started_agent_message_warns() {
    let mut stream = Vec::new();
    stream.extend_from_slice(
        format!("{{\"type\":\"thread.started\",\"thread_id\":\"{THREAD_ID}\"}}\n").as_bytes(),
    );
    stream.extend_from_slice(
        b"{\"type\":\"item.started\",\"item\":{\"id\":\"i\",\"type\":\"agent_message\",\"text\":\"x\"}}\n",
    );
    stream.extend_from_slice(
        b"{\"type\":\"item.completed\",\"item\":{\"id\":\"i\",\"type\":\"agent_message\",\"text\":\"x\"}}\n",
    );
    stream.extend_from_slice(
        b"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1,\"cached_input_tokens\":0,\"output_tokens\":1,\"reasoning_output_tokens\":0}}\n",
    );
    let workdir = tmpdir();
    let run = start_with(play_stdout(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(warning_messages(&ev), ["unrecognized codex item"]);
}

/// `TestFirstTurnCompletedWins` — the first usage report stands; a
/// second turn.completed warns "duplicate turn completion".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_turn_completed_wins() {
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("usage-second-wins-skip.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let usage: Vec<_> = ev
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::UsageReport(u)) => Some(u.usage),
            _ => None,
        })
        .collect();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].tokens_in, 300);
    assert_eq!(warning_messages(&ev), ["duplicate turn completion"]);
}

/// `TestResumeMismatchStops` — a resumed session whose thread_id
/// differs stops with session_mismatch and kills the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_mismatch_stops() {
    let workdir = tmpdir();
    let release = Arc::new(Notify::new());
    let l = ScriptedLauncher::new(play_held(fixture("resume.ndjson"), 0, release.clone()));
    let a = new_adapter(l.clone());
    // Resume under a DIFFERENT id than the fixture reports.
    let s: Arc<dyn Session> = Arc::from(
        a.resume(
            SessionRef {
                harness_session_id: "00000000-0000-4000-8000-000000000000".to_string(),
            },
            start_spec(&workdir),
        )
        .await
        .expect("resume"),
    );
    let ev = collect(&*s).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_session_mismatch");
    assert!(l.last_session().kill_count() >= 1, "mismatch must kill");
    let _ = release;
}

/// `TestResumeSameIDContinues` — resume whose thread_id matches
/// proceeds normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_same_id_continues() {
    let workdir = tmpdir();
    let l = ScriptedLauncher::new(play_stdout(fixture("resume.ndjson"), 0));
    let a = new_adapter(l);
    let s: Arc<dyn Session> = Arc::from(
        a.resume(
            SessionRef {
                harness_session_id: "dddddddd-dddd-4ddd-dddd-dddddddddddd".to_string(),
            },
            start_spec(&workdir),
        )
        .await
        .expect("resume"),
    );
    let ev = collect(&*s).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    assert!(warning_messages(&ev).is_empty());
}

/// `TestMidstreamMismatchStops` — a second thread.started with a
/// different id stops the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn midstream_mismatch_stops() {
    let mut stream = Vec::new();
    stream.extend_from_slice(
        format!("{{\"type\":\"thread.started\",\"thread_id\":\"{THREAD_ID}\"}}\n").as_bytes(),
    );
    stream.extend_from_slice(
        b"{\"type\":\"item.completed\",\"item\":{\"id\":\"i\",\"type\":\"agent_message\",\"text\":\"before\"}}\n",
    );
    stream.extend_from_slice(
        b"{\"type\":\"thread.started\",\"thread_id\":\"eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee\"}\n",
    );
    let workdir = tmpdir();
    let run = start_with(play_stdout(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_session_mismatch");
}

/// `TestSameIDRepeatIgnored` — a repeated identical thread.started is
/// a no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_id_repeat_ignored() {
    let mut stream = Vec::new();
    let line = format!("{{\"type\":\"thread.started\",\"thread_id\":\"{THREAD_ID}\"}}\n");
    stream.extend_from_slice(line.as_bytes());
    stream.extend_from_slice(line.as_bytes());
    stream.extend_from_slice(
        b"{\"type\":\"item.completed\",\"item\":{\"id\":\"i\",\"type\":\"agent_message\",\"text\":\"ok\"}}\n",
    );
    let workdir = tmpdir();
    let run = start_with(play_stdout(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    let started: Vec<_> = ev
        .iter()
        .filter(|e| matches!(e.payload, Some(EventPayload::SessionStarted(_))))
        .collect();
    assert_eq!(started.len(), 1);
    assert!(warning_messages(&ev).is_empty());
}

/// `TestOversizeLineStops` — a line past the 16 MiB cap stops the
/// session with protocol_error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversize_line_stops() {
    let mut stream = Vec::new();
    stream.extend_from_slice(
        format!("{{\"type\":\"thread.started\",\"thread_id\":\"{THREAD_ID}\"}}\n").as_bytes(),
    );
    // A line over 16 MiB: a huge string value inside a frame.
    stream.extend_from_slice(b"{\"type\":\"turn.started\",\"pad\":\"");
    stream.extend(std::iter::repeat_n(b'a', (16 << 20) + 64));
    stream.extend_from_slice(b"\"}\n");
    let workdir = tmpdir();
    let run = start_with(play_stdout(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_protocol_error");
}

/// `TestTerminalTable` — terminal mapping: clean exit, nonzero exit,
/// turn.failed, mismatch-stop; saw_failed dominates the exit code.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_table() {
    // Empty stream, exit 0 → succeeded.
    let workdir = tmpdir();
    let run = start_with(play_stdout(Vec::new(), 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    // Empty stream, exit 1 → exited_without_result.
    let workdir = tmpdir();
    let run = start_with(play_stdout(Vec::new(), 1), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_exited_without_result");
    assert_eq!(t.exit_code, Some(1));
    // turn.failed + exit 0 → api_error.
    let mut stream = Vec::new();
    stream.extend_from_slice(
        format!("{{\"type\":\"thread.started\",\"thread_id\":\"{THREAD_ID}\"}}\n").as_bytes(),
    );
    stream.extend_from_slice(b"{\"type\":\"turn.failed\",\"error\":{\"message\":\"m\"}}\n");
    let workdir = tmpdir();
    let run = start_with(play_stdout(stream, 0), start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, "harness_api_error");
    assert_eq!(t.exit_code, Some(0));
    // A success fixture exiting nonzero → exited_without_result.
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("success.ndjson"), 2),
        start_spec(&workdir),
    )
    .await;
    let ev = collect(&*run.session).await;
    let t = terminal_of(&ev);
    assert_eq!(t.reason, "harness_exited_without_result");
    assert_eq!(t.exit_code, Some(2));
}

/// `TestRefClosesUnresolvedOnEmptyStream` — no thread.started → the
/// ref channel reports None (upstream's closed channel).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ref_closes_unresolved_on_empty_stream() {
    let workdir = tmpdir();
    let run = start_with(play_stdout(Vec::new(), 0), start_spec(&workdir)).await;
    let _ = collect(&*run.session).await;
    assert!(run.session.session_ref().await.is_none());
}

/// `TestKillEndsKilled` — Kill before the terminal ends the session
/// killed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_ends_killed() {
    let workdir = tmpdir();
    let release = Arc::new(Notify::new());
    let run = start_with(
        play_held(fixture("success.ndjson"), 0, release),
        start_spec(&workdir),
    )
    .await;
    // Let the fixture play, then kill while the process holds.
    tokio::time::sleep(Duration::from_millis(100)).await;
    run.session.kill().await.unwrap();
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Killed);
    assert!(run.launcher.last_session().kill_count() >= 1);
}

/// `TestInterruptSendRespond` — unsupported/ended/no-pending errors.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupt_send_respond() {
    let workdir = tmpdir();
    let release = Arc::new(Notify::new());
    let run = start_with(play_held(Vec::new(), 0, release), start_spec(&workdir)).await;
    let err = run
        .session
        .interrupt()
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(&err, central_harness::port::codes::UNSUPPORTED));
    let err = run
        .session
        .send(OperatorInput {
            text: "x".to_string(),
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(&err, central_harness::port::codes::UNSUPPORTED));
    let err = run
        .session
        .respond_permission(PermissionDecision {
            request_id: "r".to_string(),
            allow: true,
            option_id: String::new(),
            decided_by: "t".to_string(),
            input_sha256: [0; 32],
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(
        &err,
        central_harness::port::codes::NO_PENDING_PERMISSION
    ));
    run.session.kill().await.unwrap();
    let _ = collect(&*run.session).await;
    // After the terminal, Interrupt reports session-ended.
    let err = run
        .session
        .interrupt()
        .await
        .err()
        .unwrap_or_else(|| unreachable!("expected refusal"));
    assert!(is_code(&err, central_harness::port::codes::SESSION_ENDED));
}

/// `TestStdinDelivery` — the prompt is written to stdin and stdin
/// closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_delivery() {
    let workdir = tmpdir();
    let run = start_with(
        play_stdout(fixture("success.ndjson"), 0),
        start_spec(&workdir),
    )
    .await;
    let _ = collect(&*run.session).await;
    let p = run.launcher.last_session();
    assert_eq!(
        p.stdin_written(),
        b"marker-prompt- Run the Bash command: echo probe".to_vec()
    );
}

/// `TestStdinDeliveryFailureWarns` — a write failure warns
/// "delivering the prompt failed"; the terminal still comes from the
/// exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdin_delivery_failure_warns() {
    // The script exits without ever attaching a stdin reader — the
    // write fails like a dead pipe.
    let script: Script = Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let _ = p.emit_raw(b"").await;
            p.exit(ExitStatus {
                code: 0,
                signaled: false,
            });
        })
    });
    let workdir = tmpdir();
    let run = start_with(script, start_spec(&workdir)).await;
    let ev = collect(&*run.session).await;
    assert_eq!(terminal_of(&ev).status, TerminalStatus::Succeeded);
    assert_eq!(warning_messages(&ev), ["delivering the prompt failed"]);
}

/// `TestFixtureHygiene` — every fixture is UTF-8 NDJSON; each line
/// parses through the crate scanner.
#[test]
fn fixture_hygiene() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex");
    let mut count = 0usize;
    for e in std::fs::read_dir(&dir).unwrap() {
        let e = e.unwrap();
        if e.path().extension().and_then(|s| s.to_str()) != Some("ndjson") {
            continue;
        }
        count += 1;
        let bytes = std::fs::read(e.path()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            assert!(
                serde_json::from_str::<serde_json::Value>(line).is_ok(),
                "{}:{} not JSON",
                e.file_name().to_string_lossy(),
                i + 1
            );
        }
    }
    assert!(count >= 10, "expected the verbatim fixture set");
}
