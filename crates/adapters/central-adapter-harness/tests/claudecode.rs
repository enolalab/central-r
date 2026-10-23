//! `scripted_test.go` + `session_test.go` + `permission_bridge_test.go`
//! — the scripted fake-harness tests over the verbatim `testdata/`
//! fixtures. A `scriptedLauncher` answers the `--version` and
//! `auth status` probes with fixed output and hands every session
//! launch to a scripted in-memory `Process`; the playScript port
//! replays fixture lines exactly as upstream's does.

// Integration-test helpers are not `#[test]`-annotated items, so the
// workspace's `allow-*-in-tests` clippy config does not reach them;
// relax the test-only lints for the whole file (`panic` stays denied
// everywhere — assertions use `assert!`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use central_adapter_harness::claudecode::{self, ClaudeCode, Config};
use central_foundation::failure::Failure;
use central_foundation::identity::{HarnessAttemptId, RunId, WorkspaceId};
use central_harness::approval::MAX_BRIDGED_INPUT_BYTES;
use central_harness::attempt::{Attempt, PrepareInput};
use central_harness::budget::Budget;
use central_harness::domain::{Fence, Kind, PermissionPolicy, Terminal, TerminalStatus, Workspace};
use central_harness::event::{
    Event, EventKind, EventPayload, MessageRole, ToolStatus, Usage, UsageScope,
};
use central_harness::port::{
    Adapter as _, ExitStatus, LaunchEnv, OperatorInput, PermissionDecision, PortFuture, Process,
    ProcessLauncher, ProcessSpec, ReconcileInput, Session, SessionRef, StartSpec,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

/// The fixed session id of every sanitized fixture — upstream
/// `fixtureSession`. The attempt id is the session id.
const FIXTURE_SESSION: &str = "0192f000-0000-7000-8000-000000000001";
const SESSION_ID: &str = FIXTURE_SESSION;

/// `interruptIDMarker` — replaced with the request id of the last
/// interrupt the adapter wrote (upstream `interruptIDMarker`).
const INTERRUPT_ID_MARKER: &str = "central:interrupt-id";

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/claudecode")
        .join(name);
    std::fs::read(p).unwrap()
}

fn fixture_attempt() -> HarnessAttemptId {
    HarnessAttemptId::parse(FIXTURE_SESSION).unwrap_or_else(|_| HarnessAttemptId::new())
}

/// `startSpec(t, policy)`.
fn start_spec(policy: PermissionPolicy) -> StartSpec {
    StartSpec {
        attempt: fixture_attempt(),
        fence: Fence { generation: 1 },
        workspace: Workspace {
            path: "/workspace".to_string(),
            base_sha: "abc123".to_string(),
        },
        prompt: "Run the Bash command: echo probe > probe.txt".to_string(),
        model: String::new(),
        permission: policy,
        limits: Default::default(),
        env: LaunchEnv {
            vars: [
                ("PATH".to_string(), "/usr/bin:/bin".to_string()),
                ("LANG".to_string(), "C.UTF-8".to_string()),
            ]
            .into_iter()
            .collect(),
            sandbox_scope_id: "scope-1".to_string(),
        },
    }
}

// =====================================================================
// scripted_test.go — the in-memory port.Process and scripted launcher
// =====================================================================

/// `transcript` — records the frames the adapter wrote, in order.
#[derive(Clone, Default)]
struct Transcript {
    inner: Arc<TrInner>,
}

#[derive(Default)]
struct TrInner {
    frames: Mutex<Vec<Value>>,
    lines: Mutex<Vec<String>>,
    notify: Notify,
    eof_flag: AtomicBool,
    eof: Notify,
}

impl Transcript {
    /// `read` — decodes adapter-written bytes into lines and frames.
    async fn read(&self, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = rx.recv().await {
            buf.extend_from_slice(&chunk);
            while let Some(nl) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=nl).collect();
                let text = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                let frame = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
                {
                    let mut fs = self.inner.frames.lock().unwrap();
                    fs.push(frame);
                    self.inner.lines.lock().unwrap().push(text);
                }
                self.inner.notify.notify_one();
            }
        }
        self.inner.eof_flag.store(true, Ordering::SeqCst);
        self.inner.eof.notify_waiters();
    }

    fn count(&self) -> usize {
        self.inner.frames.lock().unwrap().len()
    }

    fn all(&self) -> Vec<String> {
        self.inner.lines.lock().unwrap().clone()
    }

    fn frames(&self) -> Vec<Value> {
        self.inner.frames.lock().unwrap().clone()
    }

    /// `awaitCount` — blocks until the adapter has written `n` frames.
    async fn await_count(&self, n: usize) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if self.count() >= n {
                return true;
            }
            if self.inner.eof_flag.load(Ordering::SeqCst) {
                return self.count() >= n;
            }
            let n1 = self.inner.notify.notified();
            let n2 = self.inner.eof.notified();
            tokio::select! {
                _ = n1 => {}
                _ = n2 => {}
                _ = tokio::time::sleep_until(deadline) => return false,
            }
        }
    }

    /// `awaitFrame` — blocks until a written frame satisfies `f`.
    async fn await_frame(&self, f: impl Fn(&Value) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if self.frames().iter().any(&f) {
                return true;
            }
            if self.inner.eof_flag.load(Ordering::SeqCst) {
                return false;
            }
            let n1 = self.inner.notify.notified();
            let n2 = self.inner.eof.notified();
            tokio::select! {
                _ = n1 => {}
                _ = n2 => {}
                _ = tokio::time::sleep_until(deadline) => return false,
            }
        }
    }

    /// `awaitEof` — adapter closed stdin.
    async fn await_eof(&self) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if self.inner.eof_flag.load(Ordering::SeqCst) {
                return true;
            }
            let n = self.inner.eof.notified();
            tokio::select! {
                _ = n => {}
                _ = tokio::time::sleep_until(deadline) => return false,
            }
        }
    }

    /// `lastRequestID` — the request id of the last host control
    /// request of the given subtype, or "".
    fn last_request_id(&self, subtype: &str) -> String {
        for f in self.inner.frames.lock().unwrap().iter().rev() {
            if f["type"] == "control_request" && request_subtype(f) == subtype {
                return f["request_id"].as_str().unwrap_or("").to_string();
            }
        }
        String::new()
    }
}

fn request_subtype(f: &Value) -> &str {
    f["request"]["subtype"].as_str().unwrap_or("")
}

/// `io_closed` — the `io.ErrClosedPipe`-shaped write failure.
fn io_closed() -> Failure {
    Failure::new(
        central_foundation::failure::FailureKind::Internal,
        "E_IO",
        "stdin closed",
    )
}

/// `scriptedProcess` — an in-memory `port.Process`: the script plays
/// fixture frames on stdout and reads what the adapter writes on stdin.
struct ScriptedProcess {
    scope: String,
    /// adapter → script (stdin)
    stdin_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    stdin_rx: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    stdin_dead: AtomicBool,
    /// `io.Pipe` backpressure: while set, `write_stdin` pends until
    /// stdin dies — a harness that stopped reading.
    stdin_blocking: AtomicBool,
    stdin_gate: Notify,
    /// script → adapter (stdout); `exit` drops the sender for EOF.
    stdout_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    stdout_rx: AsyncMutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    stdout_left: Mutex<VecDeque<u8>>,
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
            stdin_dead: AtomicBool::new(false),
            stdin_blocking: AtomicBool::new(false),
            stdin_gate: Notify::new(),
            stdout_tx: Mutex::new(Some(stdout_tx)),
            stdout_rx: AsyncMutex::new(stdout_rx),
            stdout_left: Mutex::new(VecDeque::new()),
            stderr: Mutex::new(b"account: operator-probe@example.com\n".to_vec()),
            exited: Notify::new(),
            status: Mutex::new(None),
            kills: AtomicUsize::new(0),
        })
    }

    fn take_stdin_rx(&self) -> mpsc::UnboundedReceiver<Vec<u8>> {
        self.stdin_rx.lock().unwrap().take().expect("stdin rx once")
    }

    /// `exit` — closes stdout and stdin like upstream's `p.exit`.
    fn exit(&self, status: ExitStatus) {
        let mut st = self.status.lock().unwrap();
        if st.is_some() {
            return;
        }
        *st = Some(status);
        drop(st);
        // Closing the pipe ends the reader after queued bytes drain —
        // same as upstream closing `stdoutW`.
        self.stdout_tx.lock().unwrap().take();
        // Upstream closes `stdinR`, so a writer in flight fails.
        self.stdin_tx.lock().unwrap().take();
        self.stdin_dead.store(true, Ordering::SeqCst);
        self.stdin_gate.notify_waiters();
        self.exited.notify_waiters();
    }

    /// `set_stdin_blocking` — while `v` holds, a `write_stdin` never
    /// accepts a byte until stdin dies: upstream's `io.Pipe` blocks a
    /// writer when the reader stopped reading.
    fn set_stdin_blocking(&self, v: bool) {
        self.stdin_blocking.store(v, Ordering::SeqCst);
        if !v {
            self.stdin_gate.notify_waiters();
        }
    }

    /// `stdinR.CloseWithError` — the harness's stdin breaks: every
    /// pending and future write fails.
    fn break_stdin(&self) {
        self.stdin_dead.store(true, Ordering::SeqCst);
        self.stdin_tx.lock().unwrap().take();
        self.stdin_gate.notify_waiters();
    }

    /// Emit one fixture line on stdout (adds the newline).
    async fn emit_line(&self, line: &[u8]) -> Result<(), ()> {
        if self.status.lock().unwrap().is_some() {
            return Err(());
        }
        let mut l = line.to_vec();
        l.push(b'\n');
        self.emit_raw(&l).await
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

    fn write_stdin<'a>(&'a self, buf: &'a [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            loop {
                if self.stdin_dead.load(Ordering::SeqCst) {
                    return Err(io_closed());
                }
                if !self.stdin_blocking.load(Ordering::SeqCst) {
                    break;
                }
                // Backpressured: pend until stdin dies or the block lifts.
                let gate = self.stdin_gate.notified();
                let exited = self.exited.notified();
                tokio::select! {
                    () = gate => {}
                    () = exited => {}
                }
            }
            let tx = self.stdin_tx.lock().unwrap().clone();
            match tx {
                Some(tx) => tx
                    .send(buf.to_vec())
                    .map(|_| buf.len())
                    .map_err(|_| io_closed()),
                None => Err(io_closed()),
            }
        })
    }

    fn close_stdin(&self) -> PortFuture<'_, Result<(), Failure>> {
        Box::pin(async move {
            self.stdin_tx.lock().unwrap().take();
            Ok(())
        })
    }

    fn read_stdout<'a>(&'a self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, Failure>> {
        Box::pin(async move {
            loop {
                {
                    let mut left = self.stdout_left.lock().unwrap();
                    if !left.is_empty() {
                        let n = left.len().min(buf.len());
                        for b in buf.iter_mut().take(n) {
                            *b = left.pop_front().unwrap();
                        }
                        return Ok(n);
                    }
                }
                match self.stdout_rx.lock().await.recv().await {
                    Some(chunk) => {
                        self.stdout_left.lock().unwrap().extend(chunk);
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

    /// `Kill` — the launcher's kill ladder on claude: SIGTERM ends it
    /// with 143 and no result line.
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
    auth_out: Mutex<String>,
    auth_code: Mutex<i32>,
    alive: Mutex<std::collections::HashMap<String, bool>>,
    launch_err: Mutex<Option<Failure>>,
    script: Mutex<Option<Script>>,
    sessions: Mutex<Vec<Arc<ScriptedProcess>>>,
}

impl ScriptedLauncher {
    fn new(script: Script) -> Arc<Self> {
        Arc::new(Self {
            launches: Mutex::new(Vec::new()),
            version: Mutex::new("2.1.283 (Claude Code)\n".to_string()),
            auth_out: Mutex::new(String::new()),
            auth_code: Mutex::new(0),
            alive: Mutex::new(std::collections::HashMap::new()),
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

    fn set_auth(&self, out: &str, code: i32) {
        // auth_out/auth_code are plain fields upstream; keep them behind
        // the launch mutex pattern here for the same effect.
        *self.auth_out.lock().unwrap() = out.to_string();
        *self.auth_code.lock().unwrap() = code;
    }

    fn set_launch_err(&self, e: Failure) {
        *self.launch_err.lock().unwrap() = Some(e);
    }

    fn set_alive(&self, scope: &str, alive: bool) {
        self.alive.lock().unwrap().insert(scope.to_string(), alive);
    }

    fn launches(&self) -> Vec<ProcessSpec> {
        self.launches.lock().unwrap().clone()
    }

    fn session_launches(&self) -> Vec<ProcessSpec> {
        self.launches
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.args.first().is_some_and(|a| a == "-p"))
            .cloned()
            .collect()
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
                    code: 0,
                }) as Box<dyn Process>);
            }
            if spec.args.as_slice() == ["auth", "status"] {
                return Ok(Box::new(StaticProcess {
                    scope: spec.scope_id.clone(),
                    stdout: Mutex::new(self.auth_out.lock().unwrap().as_bytes().to_vec()),
                    stderr: Mutex::new(b"email operator-probe@example.com\n".to_vec()),
                    code: *self.auth_code.lock().unwrap(),
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
        Box::pin(async move { Ok(*self.alive.lock().unwrap().get(scope_id).unwrap_or(&false)) })
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

/// `playOptions`.
#[derive(Default, Clone, Copy)]
struct PlayOpts {
    exit_code: i32,
    end_without_result: bool,
}

/// `playScript` — the generic claude stand-in. Expects initialize and
/// the user message, then plays the fixture: after a `can_use_tool`
/// request it waits for the adapter's control_response; an `await`
/// marker waits for the named host control request;
/// `interruptIDMarker` is replaced with the last interrupt's request
/// id; after the last result it waits for stdin to close and exits.
fn play_script(fixture: Vec<u8>, tr: Transcript, opts: PlayOpts) -> Script {
    Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let tr2 = tr.clone();
            let rx = p.take_stdin_rx();
            tokio::spawn(async move { tr2.read(rx).await });
            if !tr.await_count(2).await {
                p.exit(ExitStatus {
                    code: 1,
                    signaled: false,
                });
                return;
            }
            let mut written = 2usize;
            let mut saw_result = false;
            let text = String::from_utf8_lossy(&fixture).into_owned();
            for line in text.trim_end_matches('\n').split('\n') {
                if line.is_empty() {
                    continue;
                }
                let f: Value = serde_json::from_str(line).unwrap_or(Value::Null);
                if f["central_fixture"] == "await" {
                    let want = f["request"].as_str().unwrap_or("");
                    if !tr
                        .await_frame(|f| {
                            f["type"] == "control_request" && request_subtype(f) == want
                        })
                        .await
                    {
                        p.exit(ExitStatus {
                            code: 1,
                            signaled: false,
                        });
                        return;
                    }
                    written = tr.count();
                    continue;
                }
                let line = line.replace(INTERRUPT_ID_MARKER, &tr.last_request_id("interrupt"));
                if p.emit_line(line.as_bytes()).await.is_err() {
                    return; // killed
                }
                if f["type"] == "control_request" {
                    written += 1;
                    if !tr.await_count(written).await {
                        p.exit(ExitStatus {
                            code: 1,
                            signaled: false,
                        });
                        return;
                    }
                }
                if f["type"] == "result"
                    && (f["queued_turn_count"].is_null()
                        || f["queued_turn_count"].as_u64() == Some(0))
                {
                    saw_result = true;
                }
            }
            if saw_result {
                tr.await_eof().await;
                p.exit(ExitStatus {
                    code: opts.exit_code,
                    signaled: false,
                });
                return;
            }
            if opts.end_without_result {
                p.exit(ExitStatus {
                    code: 1,
                    signaled: false,
                });
                return;
            }
            p.exited_wait().await;
        })
    })
}

/// `run` — adapter + launcher + transcript + session.
struct Run {
    launcher: Arc<ScriptedLauncher>,
    tr: Transcript,
    session: Arc<dyn Session>,
}

fn new_adapter(l: Arc<dyn ProcessLauncher>) -> ClaudeCode {
    ClaudeCode::new(Config {
        launcher: Some(l),
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .unwrap()
}

async fn start_with(fixture: &[u8], spec: StartSpec, opts: PlayOpts) -> Run {
    let tr = Transcript::default();
    let l = ScriptedLauncher::new(play_script(fixture.to_vec(), tr.clone(), opts));
    let a = new_adapter(l.clone());
    let s: Arc<dyn Session> = Arc::from(a.start(spec).await.expect("start"));
    Run {
        launcher: l,
        tr,
        session: s,
    }
}

/// `collect` — drains every event; fails if the channel does not
/// close. Every event must validate and have a strictly increasing seq.
async fn collect(s: &dyn Session, mut on: impl FnMut(&Event)) -> Vec<Event> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, s.next_event())
            .await
            .expect("timed out collecting events")
        {
            Some(e) => {
                e.validate().expect("invalid event");
                assert_eq!(e.seq as usize, out.len() + 1, "seq");
                on(&e);
                out.push(e);
            }
            None => return out,
        }
    }
}

fn kinds(events: &[Event]) -> Vec<EventKind> {
    events
        .iter()
        .map(|e| e.payload.as_ref().map(|p| p.event_kind()))
        .collect::<Option<Vec<_>>>()
        .expect("every event has a payload")
}

/// `terminalOf` — the LAST event must be a `TerminalReported` (the Go
/// helper's type assertion on `events[len-1]`).
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

// =====================================================================
// session_test.go — happy path, fixtures, terminal mapping
// =====================================================================

/// `TestSuccess` — the success fixture plays end to end: session
/// started, the assistant message, usage, then a Succeeded terminal;
/// stdin carried initialize + the prompt; the prompt is never on argv.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn success_fixture() {
    let r = start_with(
        &fixture("success.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let k = kinds(&events);
    assert_eq!(k.first(), Some(&EventKind::SessionStarted));
    assert!(k.contains(&EventKind::Message));
    assert!(k.contains(&EventKind::UsageReport));
    assert_eq!(k.last(), Some(&EventKind::TerminalReported));
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Succeeded, "{t:?}");

    // stdin: initialize then the user prompt.
    let frames = r.tr.frames();
    assert_eq!(
        frames[0]["request"]["subtype"].as_str().unwrap_or(""),
        "initialize"
    );
    assert_eq!(frames[1]["type"].as_str().unwrap_or(""), "user");
    // The prompt is never on argv.
    let launch = r.launcher.session_launches();
    assert_eq!(launch.len(), 1);
    assert!(!launch[0].args.iter().any(|a| a.contains("echo probe")));
    assert!(launch[0].args.windows(2).any(|w| w[0] == "--session-id"));
}

/// `TestResumeKeepsTheSessionID` — resume passes `--resume` and the
/// fixture's id, the revealed session keeps it; an empty or
/// option-looking ref is refused before launch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_keeps_the_session_id() {
    let tr = Transcript::default();
    let l = ScriptedLauncher::new(play_script(
        fixture("resume.ndjson"),
        tr.clone(),
        PlayOpts::default(),
    ));
    let a = new_adapter(l.clone());
    let mut spec = start_spec(PermissionPolicy::Bridge);
    // A new attempt resumes the old session.
    spec.attempt = HarnessAttemptId::new();
    let s = a
        .resume(
            SessionRef {
                harness_session_id: FIXTURE_SESSION.to_string(),
            },
            spec.clone(),
        )
        .await
        .expect("resume");
    let events = collect(&*s, |_| {}).await;
    match &events[0].payload {
        Some(EventPayload::SessionStarted(started)) => {
            assert_eq!(started.harness_session_id, FIXTURE_SESSION);
        }
        other => unreachable!("first event = {other:?}"),
    }
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    let launch = l.session_launches();
    assert!(
        launch[0]
            .args
            .windows(2)
            .any(|w| w == ["--resume", FIXTURE_SESSION])
    );
    assert!(!launch[0].args.iter().any(|a| a == "--session-id"));

    let err = a
        .resume(SessionRef::default(), spec.clone())
        .await
        .err()
        .unwrap_or_else(|| unreachable!("empty ref succeeded"));
    assert!(is_code(&err, claudecode::codes::INVALID_LAUNCH), "{err}");
    let err = a
        .resume(
            SessionRef {
                harness_session_id: "--settings".to_string(),
            },
            spec,
        )
        .await
        .err()
        .unwrap_or_else(|| unreachable!("option-looking ref succeeded"));
    assert!(is_code(&err, claudecode::codes::INVALID_LAUNCH), "{err}");
}

/// `TestInterruptEndsInterrupted` — respond to the fixture's permission
/// request, interrupt mid-turn; the harness acks and ends Interrupted
/// with an error tool result; after the end, Interrupt and Send both
/// refuse SESSION_ENDED.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupt_ends_interrupted() {
    let r = start_with(
        &fixture("interrupt.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts {
            exit_code: 1,
            ..PlayOpts::default()
        },
    )
    .await;
    // Drain until the permission request; respond + interrupt (the
    // fixture's await marker holds for the interrupt request).
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let e = tokio::time::timeout_at(deadline, r.session.next_event())
            .await
            .expect("timed out awaiting permission request")
            .expect("stream closed before the request");
        e.validate().expect("invalid event");
        let is_req = matches!(&e.payload, Some(EventPayload::PermissionRequested(_)));
        events.push(e);
        if is_req {
            break;
        }
    }
    let Some(EventPayload::PermissionRequested(p)) = events.last().and_then(|e| e.payload.clone())
    else {
        unreachable!("no permission request");
    };
    let digest: [u8; 32] = Sha256::digest(&p.input).into();
    r.session
        .respond_permission(PermissionDecision {
            request_id: p.request_id.clone(),
            allow: true,
            option_id: String::new(),
            decided_by: "operator".to_string(),
            input_sha256: digest,
        })
        .await
        .expect("respond");
    r.session.interrupt().await.expect("interrupt");
    while let Some(e) = r.session.next_event().await {
        e.validate().expect("invalid event");
        events.push(e);
    }
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Interrupted, "{t:?}");
    assert_eq!(t.reason, claudecode::reasons::HARNESS_ABORTED);
    assert_eq!(exit_code(&t), 1);
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            Some(EventPayload::ToolResult(tr)) if tr.status == ToolStatus::Error
        )),
        "no error tool result: {:?}",
        kinds(&events)
    );
    let lines = r.tr.all();
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert!(
        lines[3].contains("\"request\":{\"subtype\":\"interrupt\"}"),
        "{lines:?}"
    );
    let err = r
        .session
        .interrupt()
        .await
        .err()
        .unwrap_or_else(|| unreachable!("interrupt after end succeeded"));
    assert!(
        is_code(&err, central_harness::port::codes::SESSION_ENDED),
        "{err}"
    );
    let err = r
        .session
        .send(OperatorInput {
            text: "more".to_string(),
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("send after end succeeded"));
    assert!(
        is_code(&err, central_harness::port::codes::SESSION_ENDED),
        "{err}"
    );
}

/// `TestKillEndsKilledWithoutResult` — kill on the first Reasoning
/// event; the terminal is Killed with the SIGTERM exit 143 and no
/// result; a second Kill still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_ends_killed_without_result() {
    let r = start_with(
        &fixture("sigterm-no-result.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let mut events = Vec::new();
    let mut killed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
        .await
        .expect("timed out collecting events")
    {
        e.validate().expect("invalid event");
        if matches!(&e.payload, Some(EventPayload::Reasoning(_))) && !killed {
            killed = true;
            r.session.kill().await.expect("kill");
        }
        events.push(e);
    }
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Killed);
    assert!(t.reason.is_empty());
    assert_eq!(exit_code(&t), 143);
    // Kill after the end is still Ok.
    r.session.kill().await.expect("kill after end");
}

/// `TestStreamEndWithoutResultFails` — EOF with no result frame is a
/// failure the adapter did not kill for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_end_without_result_fails() {
    let r = start_with(
        &fixture("sigterm-no-result.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts {
            exit_code: 1,
            end_without_result: true,
        },
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_EXITED_WITHOUT_RESULT);
    assert_eq!(exit_code(&t), 1);
    assert_eq!(
        r.launcher.last_session().kill_count(),
        0,
        "adapter killed a process that ended on its own"
    );
}

/// `TestNotAuthenticated` — the fixture ends with an api_error result;
/// the assistant message's zero usage has no live report, so the one
/// report is the result's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_authenticated_fixture() {
    let r = start_with(
        &fixture("not-authenticated.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts {
            exit_code: 1,
            ..PlayOpts::default()
        },
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let want = [
        EventKind::SessionStarted,
        EventKind::Message,
        EventKind::UsageReport,
        EventKind::TerminalReported,
    ];
    assert_eq!(kinds(&events), want.as_slice());
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_NOT_AUTHENTICATED);
    assert_eq!(exit_code(&t), 1);
}

/// `TestMiscFramesMapping` — the §5 rows the captured sessions do not
/// cover: api_retry, frames that are never emitted, an unknown type and
/// a malformed line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn misc_frames() {
    let r = start_with(
        &fixture("misc-frames.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let want = [
        EventKind::SessionStarted,
        EventKind::Retry,
        EventKind::Warning,
        EventKind::Warning,
        // msg_misc2 reports its tokens live; its usage has no
        // cache_creation_input_tokens, which counts as 0.
        EventKind::UsageReport,
        EventKind::Message,
        EventKind::UsageReport,
        EventKind::Message,
        EventKind::TerminalReported,
    ];
    let k = kinds(&events);
    assert_eq!(k, want.as_slice(), "{k:?}");
    match &events[1].payload {
        Some(EventPayload::Retry(p)) => assert_eq!(p.reason, "api_retry"),
        other => unreachable!("retry = {other:?}"),
    }
    match &events[2].payload {
        Some(EventPayload::Warning(p)) => {
            assert_eq!(p.message, "unrecognized harness message");
            assert!(String::from_utf8_lossy(&events[2].raw).contains("future_frame_kind"));
        }
        other => unreachable!("unknown type warning = {other:?}"),
    }
    match &events[3].payload {
        Some(EventPayload::Warning(p)) => assert_eq!(p.message, "malformed harness frame"),
        other => unreachable!("malformed warning = {other:?}"),
    }
    match &events[4].payload {
        Some(EventPayload::UsageReport(u)) => {
            assert_eq!(u.usage, cumulative(1, 1, 0, 0, 0), "{:?}", u.usage);
        }
        other => unreachable!("live usage = {other:?}"),
    }
    match &events[5].payload {
        Some(EventPayload::Message(m)) => {
            assert_eq!(m.role, MessageRole::Assistant);
            assert_eq!(m.text, "still here");
        }
        other => unreachable!("message = {other:?}"),
    }
    match &events[6].payload {
        Some(EventPayload::UsageReport(u)) => assert_eq!(u.usage.cost_micro_usd, 71436),
        other => unreachable!("cost report = {other:?}"),
    }
    // No event text may carry the fixture's bait strings.
    for e in &events {
        let s = format!("{:?}", e.payload);
        assert!(
            !s.contains("overloaded") && !s.contains("must not leak"),
            "{s}"
        );
    }
}

/// `TestDenyPolicyPermissionDeniedBecomesDeniedResult` — a harness-side
/// denial under the deny policy yields a denied ToolResult and the run
/// still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deny_policy_permission_denied_becomes_denied_result() {
    let r = start_with(
        &fixture("policy-denied.ndjson"),
        start_spec(PermissionPolicy::Deny),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let mut results = Vec::new();
    for e in &events {
        match &e.payload {
            Some(EventPayload::ToolResult(tr)) => results.push(tr.clone()),
            Some(EventPayload::PermissionRequested(_) | EventPayload::PermissionResolved(_)) => {
                unreachable!("deny policy bridged a permission: {e:?}")
            }
            _ => {}
        }
    }
    assert_eq!(results.len(), 1, "{results:?}");
    assert_eq!(results[0].id, "toolu_0117bV9FFG43g5zuidXxAqme");
    assert_eq!(results[0].status, ToolStatus::Denied);
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    let args = r.launcher.session_launches()[0].args.join(" ");
    assert!(
        args.contains("--permission-mode dontAsk --permission-prompts none"),
        "deny argv = {args}"
    );
}

/// `TestAutoAllowAndDenySucceedWithTheirModes` — the bypassPermissions
/// and dontAsk fixtures each succeed under their own policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_allow_and_deny_succeed_with_their_modes() {
    for (policy, name) in [
        (PermissionPolicy::AutoAllow, "auto-allow-success.ndjson"),
        (PermissionPolicy::Deny, "deny-success.ndjson"),
    ] {
        let r = start_with(&fixture(name), start_spec(policy), PlayOpts::default()).await;
        let events = collect(&*r.session, |_| {}).await;
        assert_eq!(
            terminal_of(&events).status,
            TerminalStatus::Succeeded,
            "{policy}: kinds {:?}",
            kinds(&events)
        );
    }
}

// =====================================================================
// permission_bridge_test.go
// =====================================================================

/// `TestBridgeAllowStartToSucceeded` — the full bridge path against the
/// real 2.1.283 allow transcript: exact kinds, payload fields, written
/// bytes, launch argv and the ref channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_allow_start_to_succeeded() {
    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.model = "haiku".to_string();
    let r = start_with(
        &fixture("bridge-allow.ndjson"),
        spec.clone(),
        PlayOpts::default(),
    )
    .await;
    // Answer the bridged request as it arrives (the script blocks until
    // the control_response lands).
    let events = collect_answering(&r.session, true).await;
    let requested = events
        .iter()
        .find_map(|e| match &e.payload {
            Some(EventPayload::PermissionRequested(p)) => Some(p.clone()),
            _ => None,
        })
        .expect("a permission request");
    let digest: [u8; 32] = Sha256::digest(&requested.input).into();
    let want = [
        // Each of the two main-thread messages reports its tokens live,
        // ahead of its content events (phase 3l decision 3).
        EventKind::SessionStarted,
        EventKind::UsageReport,
        EventKind::Reasoning,
        EventKind::ToolCall,
        EventKind::PermissionRequested,
        EventKind::PermissionResolved,
        EventKind::ToolResult,
        EventKind::UsageReport,
        EventKind::Reasoning,
        EventKind::Message,
        // The result frame's text follows the usage report as the last
        // assistant Message (phase 3e decision 8).
        EventKind::UsageReport,
        EventKind::Message,
        EventKind::TerminalReported,
    ];
    let k = kinds(&events);
    assert_eq!(k, want.as_slice(), "kinds = {k:?}");
    match &events[11].payload {
        Some(EventPayload::Message(m)) => {
            assert_eq!(m.role, MessageRole::Assistant);
            assert_eq!(
                m.text,
                "Done. Created `probe.txt` with the content \"probe\"."
            );
        }
        other => unreachable!("result message = {other:?}"),
    }
    match &events[0].payload {
        Some(EventPayload::SessionStarted(started)) => {
            assert_eq!(started.harness_session_id, FIXTURE_SESSION);
            assert_eq!(started.harness_version, "2.1.283");
            assert_eq!(started.model, "claude-haiku-4-5-20251001");
            assert_eq!(started.tools.len(), 5);
            assert_eq!(started.reported_capabilities.len(), 5);
        }
        other => unreachable!("session started = {other:?}"),
    }
    for e in &events {
        assert_eq!(e.harness_session_id, FIXTURE_SESSION);
        assert_eq!(e.attempt, spec.attempt);
        assert!(!e.raw.is_empty());
    }
    match &events[3].payload {
        Some(EventPayload::ToolCall(call)) => {
            assert_eq!(call.id, "toolu_011r1UrbLM4eu7EYBqc2WYwD");
            assert_eq!(call.name, "Bash");
            assert!(
                call.input
                    .windows(b"echo probe > probe.txt".len())
                    .any(|w| w == b"echo probe > probe.txt")
            );
        }
        other => unreachable!("tool call = {other:?}"),
    }
    assert_eq!(requested.tool, "Bash");
    assert_eq!(
        requested.resources,
        vec!["/workspace/probe.txt".to_string()]
    );
    match &events[5].payload {
        Some(EventPayload::PermissionResolved(resolved)) => {
            assert_eq!(resolved.request_id, requested.request_id);
            assert_eq!(
                resolved.decision,
                central_harness::event::PermissionOutcome::Allowed
            );
            assert_eq!(resolved.decided_by, "operator");
        }
        other => unreachable!("resolved = {other:?}"),
    }
    match &events[6].payload {
        Some(EventPayload::ToolResult(res)) => {
            assert_eq!(res.id, "toolu_011r1UrbLM4eu7EYBqc2WYwD");
            assert_eq!(res.status, ToolStatus::Ok);
        }
        other => unreachable!("tool result = {other:?}"),
    }
    // The result's figures are unchanged: at or above the live sum
    // (18 in, 5 out, 35532 cache write) in every counter.
    match &events[10].payload {
        Some(EventPayload::UsageReport(u)) => {
            assert_eq!(u.usage, cumulative(18, 205, 63842, 35532, 78491));
        }
        other => unreachable!("usage = {other:?}"),
    }
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Succeeded);
    assert!(t.reason.is_empty());
    assert_eq!(exit_code(&t), 0);
    assert_eq!(wait_terminal(&*r.session).await.status, t.status);
    let session_ref = r.session.session_ref().await;
    assert_eq!(
        session_ref.map(|r| r.harness_session_id),
        Some(FIXTURE_SESSION.to_string())
    );
    // A second read sees the closed channel.
    assert!(r.session.session_ref().await.is_none());

    // What the adapter wrote: initialize, the prompt, then exactly the
    // allow answer carrying the harness's own input.
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    let frames = r.tr.frames();
    assert_eq!(frames[0]["type"], "control_request");
    assert_eq!(request_subtype(&frames[0]), "initialize");
    assert_eq!(
        lines[1],
        r#"{"type":"user","message":{"role":"user","content":"Run the Bash command: echo probe > probe.txt"}}"#
    );
    let want_allow = format!(
        "{{\"type\":\"control_response\",\"response\":{{\"subtype\":\"success\",\"request_id\":\"{}\",\"response\":{{\"behavior\":\"allow\",\"updatedInput\":{{\"command\":\"echo probe > probe.txt\",\"description\":\"Create probe.txt with the text \\\"probe\\\"\"}}}}}}}}",
        requested.request_id
    );
    assert_eq!(lines[2], want_allow, "allow frame");

    // The launch: closed argv, env from the spec only, the worktree,
    // the scope Central chose; the prompt never reaches argv.
    let launches = r.launcher.session_launches();
    assert_eq!(launches.len(), 1);
    let got = &launches[0];
    let want_args = [
        "-p",
        "--verbose",
        "--output-format",
        "stream-json",
        "--input-format",
        "stream-json",
        "--setting-sources",
        "user",
        "--session-id",
        FIXTURE_SESSION,
        "--permission-mode",
        "manual",
        "--permission-prompts",
        "host",
        "--permission-prompt-tool",
        "stdio",
        "--model",
        "haiku",
    ];
    assert_eq!(got.program, "claude");
    assert_eq!(got.args, want_args, "launch args");
    assert_eq!(got.work_dir, "/workspace");
    assert_eq!(got.scope_id, "scope-1");
    assert_eq!(got.env, spec.env.vars);
    assert!(!got.args.join(" ").contains(&spec.prompt), "prompt in argv");

    // Answering a consumed request is the benign refusal.
    let err = r
        .session
        .respond_permission(PermissionDecision {
            request_id: requested.request_id.clone(),
            allow: true,
            option_id: String::new(),
            decided_by: String::new(),
            input_sha256: digest,
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("answering twice succeeded"));
    assert!(
        is_code(&err, central_harness::port::codes::NO_PENDING_PERMISSION),
        "{err}"
    );
}

/// `TestBridgeDenyMarksToolResultDenied` — a deny answers `deny` with
/// the fixed text; the tool result reports Denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_deny_marks_tool_result_denied() {
    let r = start_with(
        &fixture("bridge-deny.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect_answering(&r.session, false).await;
    let mut resolved = None;
    let mut result = None;
    for e in &events {
        match &e.payload {
            Some(EventPayload::PermissionResolved(p)) => resolved = Some(p.clone()),
            Some(EventPayload::ToolResult(p)) => result = Some(p.clone()),
            _ => {}
        }
    }
    let resolved = resolved.expect("resolved");
    let result = result.expect("tool result");
    assert_eq!(
        resolved.decision,
        central_harness::event::PermissionOutcome::Denied
    );
    assert_eq!(result.status, ToolStatus::Denied);
    assert_eq!(result.id, "toolu_01BvXQwrnnJMDz6gJmVFZpgJ");
    let want = format!(
        "{{\"type\":\"control_response\",\"response\":{{\"subtype\":\"success\",\"request_id\":\"{}\",\"response\":{{\"behavior\":\"deny\",\"message\":\"Denied by the operator.\",\"interrupt\":false}}}}}}",
        resolved.request_id
    );
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[2], want);
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

// =====================================================================
// launch validation
// =====================================================================

/// `TestStartRefusals` — the spec's PATH policy, a credential env,
/// max-turns, an option-looking model and a launcher error each refuse
/// (or fail) before or at launch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_refusals() {
    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l.clone());

    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.env.vars.remove("PATH");
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("missing PATH succeeded"));
    assert!(is_code(&err, claudecode::codes::PATH_REQUIRED), "{err}");

    for path in UNSAFE_PATHS {
        let mut spec = start_spec(PermissionPolicy::Bridge);
        spec.env.vars.insert("PATH".to_string(), path.to_string());
        let err = a
            .start(spec.clone())
            .await
            .err()
            .unwrap_or_else(|| unreachable!("unsafe PATH start succeeded"));
        assert!(
            is_code(&err, claudecode::codes::PATH_REQUIRED),
            "PATH {path:?}: {err}"
        );
        assert!(
            path.len() <= 1 || !err.message().contains(path),
            "PATH {path:?} leaked into {err}"
        );
        let err = a
            .resume(
                SessionRef {
                    harness_session_id: FIXTURE_SESSION.to_string(),
                },
                spec,
            )
            .await
            .err()
            .unwrap_or_else(|| unreachable!("unsafe PATH resume succeeded"));
        assert!(
            is_code(&err, claudecode::codes::PATH_REQUIRED),
            "resume PATH {path:?}: {err}"
        );
    }

    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.env
        .vars
        .insert("ANTHROPIC_API_KEY".to_string(), "sk-ant-secret".to_string());
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("credential env succeeded"));
    assert!(
        is_code(&err, central_harness::domain::codes::FORBIDDEN_LAUNCH_ENV),
        "{err}"
    );
    assert!(!err.message().contains("sk-ant-secret"), "{err}");

    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.limits.max_turns = 3;
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("max turns succeeded"));
    assert!(
        is_code(&err, central_harness::port::codes::UNSUPPORTED),
        "{err}"
    );

    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.model = "--dangerously-skip-permissions".to_string();
    let err = a
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("option model succeeded"));
    assert!(is_code(&err, claudecode::codes::INVALID_LAUNCH), "{err}");

    assert_eq!(
        l.session_launches().len(),
        0,
        "refused starts launched sessions"
    );

    l.set_launch_err(Failure::new(
        central_foundation::failure::FailureKind::Internal,
        "E_BOOM",
        "boom",
    ));
    let err = a
        .start(start_spec(PermissionPolicy::Bridge))
        .await
        .err()
        .unwrap_or_else(|| unreachable!("launch error succeeded"));
    assert!(err.message().contains("boom"), "{err}");
}

/// `TestStartPassesTheNativeCostLimit` — Start launches claude with the
/// spec's cost limit as --max-budget-usd, and without the flag when
/// there is no limit (harness phase 3d decision 5).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_passes_the_native_cost_limit() {
    for (limit, want) in [(0i64, ""), (500_000, "0.50"), (2_500_000, "2.50")] {
        let tr = Transcript::default();
        let l = ScriptedLauncher::new(play_script(
            fixture("success.ndjson"),
            tr.clone(),
            PlayOpts::default(),
        ));
        let a = new_adapter(l.clone());
        let mut spec = start_spec(PermissionPolicy::Bridge);
        spec.limits.max_cost_micro_usd = limit;
        let s = a.start(spec).await.expect("start");
        let events = collect(&*s, |_| {}).await;
        assert_eq!(
            terminal_of(&events).status,
            TerminalStatus::Succeeded,
            "limit {limit}: {:?}",
            kinds(&events)
        );
        let args = &l.session_launches()[0].args;
        let got = args
            .windows(2)
            .find(|w| w[0] == "--max-budget-usd")
            .map(|w| w[1].as_str())
            .unwrap_or("");
        assert_eq!(got, want, "limit {limit}: args {args:?}");
    }
    // A sub-cent limit cannot be rendered as dollars: refused.
    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.limits.max_cost_micro_usd = 9_999;
    let l = ScriptedLauncher::unscripted();
    let err = new_adapter(l.clone())
        .start(spec)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("sub-cent limit succeeded"));
    assert!(is_code(&err, claudecode::codes::INVALID_LAUNCH), "{err}");
    assert_eq!(l.session_launches().len(), 0);
}

/// `TestStartRefusesUnpinnedVersionUnlessAllowed` — a launcher
/// reporting another version is refused unless `allow_unpinned`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_refuses_unpinned_version_unless_allowed() {
    let tr = Transcript::default();
    let l = ScriptedLauncher::new(play_script(
        fixture("success.ndjson"),
        tr,
        PlayOpts::default(),
    ));
    l.set_version("2.1.284 (Claude Code)\n");
    let a = new_adapter(l.clone());
    let err = a
        .start(start_spec(PermissionPolicy::Bridge))
        .await
        .err()
        .unwrap_or_else(|| unreachable!("unpinned succeeded"));
    assert!(is_code(&err, claudecode::codes::UNPINNED_VERSION), "{err}");
    assert_eq!(
        l.session_launches().len(),
        0,
        "unpinned start launched sessions"
    );
    let loose = ClaudeCode::new(Config {
        launcher: Some(l.clone()),
        allow_unpinned: true,
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .expect("loose adapter");
    let s = loose
        .start(start_spec(PermissionPolicy::Bridge))
        .await
        .expect("allow unpinned");
    let events = collect(&*s, |_| {}).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

// =====================================================================
// scripted_test.go tails — fixture editing and event helpers
// =====================================================================

fn is_code(err: &Failure, code: &str) -> bool {
    err.code() == code
}

/// `resultOffset` — the byte offset of the fixture's first result line.
fn result_offset(fixture: &[u8]) -> usize {
    let mut offset = 0usize;
    for line in fixture.split_inclusive(|b| *b == b'\n') {
        let is_result = serde_json::from_slice::<Value>(line)
            .ok()
            .is_some_and(|f| f["type"] == "result");
        if is_result {
            return offset;
        }
        offset += line.len();
    }
    unreachable!("fixture has no result line")
}

/// `fixtureLine` — the first line of fixture whose type and subtype
/// (the frame's own, or a control request's) match; an empty subtype
/// matches any. The returned line is '\n'-terminated.
fn fixture_line(fixture: &[u8], typ: &str, subtype: &str) -> Vec<u8> {
    for line in fixture.split(|b| *b == b'\n') {
        let Ok(f) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if f["type"] != typ {
            continue;
        }
        if subtype.is_empty() || f["subtype"] == subtype || request_subtype(&f) == subtype {
            let mut out = line.to_vec();
            out.push(b'\n');
            return out;
        }
    }
    unreachable!("no {typ} {subtype} line")
}

/// `mutateResult` — rewrite the fixture's first result frame through
/// `edit`.
fn mutate_result(
    fixture: &[u8],
    edit: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> Vec<u8> {
    let i = result_offset(fixture);
    let rest = &fixture[i..];
    let end = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
    let mut result: Value = serde_json::from_slice(&rest[..end]).expect("result frame");
    edit(result.as_object_mut().expect("result is an object"));
    let mut out = fixture[..i].to_vec();
    out.extend_from_slice(serde_json::to_string(&result).unwrap().as_bytes());
    out.extend_from_slice(&rest[end..]);
    out
}

/// `bytes.Replace(…, 1)` — the first occurrence only.
fn replace_once(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    let Some(idx) = hay.windows(needle.len()).position(|w| w == needle) else {
        unreachable!("needle not found: {}", String::from_utf8_lossy(needle));
    };
    let mut out = hay[..idx].to_vec();
    out.extend_from_slice(with);
    out.extend_from_slice(&hay[idx + needle.len()..]);
    out
}

/// `canUseTool` — the bridge-allow fixture's can_use_tool line with its
/// request edited by `edit` and its request id set to `id` ("" keeps
/// the fixture's own).
fn can_use_tool(id: &str, edit: impl FnOnce(&mut serde_json::Map<String, Value>)) -> Vec<u8> {
    let line = fixture_line(
        &fixture("bridge-allow.ndjson"),
        "control_request",
        "can_use_tool",
    );
    let mut f: Value = serde_json::from_slice(&line).expect("can_use_tool line");
    let obj = f.as_object_mut().expect("frame object");
    if !id.is_empty() {
        obj.insert("request_id".to_string(), Value::String(id.to_string()));
    }
    let req = obj
        .get_mut("request")
        .and_then(Value::as_object_mut)
        .expect("request object");
    edit(req);
    let mut out = serde_json::to_string(&f).unwrap().into_bytes();
    out.push(b'\n');
    out
}

/// `withCanUseTool` — replace the bridge-allow fixture's can_use_tool
/// line with `replacement` (which carries its own '\n').
fn with_can_use_tool(replacement: &[u8]) -> Vec<u8> {
    let fixture = fixture("bridge-allow.ndjson");
    let original = fixture_line(&fixture, "control_request", "can_use_tool");
    if fixture
        .windows(original.len())
        .any(|w| w == original.as_slice())
    {
        return replace_once(&fixture, &original, replacement);
    }
    // The line may end the file without a trailing newline.
    let o = &original[..original.len() - 1];
    let r = &replacement[..replacement.len().saturating_sub(1)];
    replace_once(&fixture, o, r)
}

/// `withMode` — rewrite the fixture init's permissionMode.
fn with_mode(fixture: &[u8], mode: &str) -> Vec<u8> {
    replace_once(
        fixture,
        br#""permissionMode":"default""#,
        format!("\"permissionMode\":\"{mode}\"").as_bytes(),
    )
}

/// `rawScript` — plays lines right after the initialize request and the
/// prompt, without waiting for any answer, then holds until killed.
fn raw_script(tr: Transcript, lines: Vec<Vec<u8>>) -> Script {
    Box::new(move |p: Arc<ScriptedProcess>| {
        Box::pin(async move {
            let tr2 = tr.clone();
            let rx = p.take_stdin_rx();
            tokio::spawn(async move { tr2.read(rx).await });
            if !tr.await_count(2).await {
                p.exit(ExitStatus {
                    code: 1,
                    signaled: false,
                });
                return;
            }
            for line in lines {
                if p.emit_raw(&line).await.is_err() {
                    return;
                }
            }
            p.exited_wait().await;
        })
    })
}

/// `startRaw` — a bridge-policy session over a raw line script.
async fn start_raw(lines: Vec<Vec<u8>>) -> Run {
    let tr = Transcript::default();
    let l = ScriptedLauncher::new(raw_script(tr.clone(), lines));
    let a = new_adapter(l.clone());
    let s: Arc<dyn Session> = Arc::from(
        a.start(start_spec(PermissionPolicy::Bridge))
            .await
            .expect("start"),
    );
    Run {
        launcher: l,
        tr,
        session: s,
    }
}

/// `usageReports` — the usage of every UsageReport in order.
fn usage_reports(events: &[Event]) -> Vec<Usage> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::UsageReport(u)) => Some(u.usage),
            _ => None,
        })
        .collect()
}

/// `messagesOf` — the assistant Message texts in order, and whether a
/// Message follows the last UsageReport.
fn messages_of(events: &[Event]) -> (Vec<String>, bool) {
    let mut texts = Vec::new();
    let mut saw_usage = false;
    let mut after_usage = false;
    for e in events {
        match &e.payload {
            Some(EventPayload::UsageReport(_)) => {
                saw_usage = true;
                after_usage = false;
            }
            Some(EventPayload::Message(m)) if m.role == MessageRole::Assistant => {
                texts.push(m.text.clone());
                if saw_usage {
                    after_usage = true;
                }
            }
            _ => {}
        }
    }
    (texts, after_usage)
}

/// `foldUsage` — applies every usage report to a launched attempt, as
/// the phase-3 app service will, and returns the attempt's folded
/// usage.
fn fold_usage(reports: &[Usage]) -> Usage {
    let fence = Fence { generation: 1 };
    let now = OffsetDateTime::now_utc();
    let a = Attempt::prepare(PrepareInput {
        id: fixture_attempt(),
        workspace_id: WorkspaceId::new(),
        run_id: RunId::new(),
        kind: Kind::new(claudecode::KIND),
        adapter_version: "0.2.0".to_string(),
        workspace: Workspace {
            path: "/work".to_string(),
            base_sha: "abc123".to_string(),
        },
        permission: PermissionPolicy::Bridge,
        fence,
        budget: Budget {
            cost_micro_usd: 5_000_000,
            wall_clock: time::Duration::minutes(30),
            ..Budget::default()
        },
        at: now,
    })
    .expect("prepare");
    let mut a = a.launch(fence, "scope-1", "2.1.283", now).expect("launch");
    for (i, u) in reports.iter().enumerate() {
        match a.apply_usage(fence, *u, now) {
            Ok(next) => a = next,
            Err(e) => unreachable!("usage report {i} {u:?}: {e}"),
        }
    }
    a.usage
}

/// `waitTerminal` — `Session::wait` bounded by a deadline.
async fn wait_terminal(s: &dyn Session) -> Terminal {
    tokio::time::timeout(Duration::from_secs(10), s.wait())
        .await
        .expect("wait timed out")
        .expect("wait")
}

/// `unsafePaths` — PATH values with an empty or relative entry, which
/// would resolve commands against the worktree (security review S2).
const UNSAFE_PATHS: &[&str] = &[
    "/usr/bin:",
    ":/usr/bin",
    "/usr/bin::/bin",
    ".:/usr/bin",
    "bin:/usr/bin",
    "/usr/bin:./bin",
    ":",
];

/// `probeEnv`.
fn probe_env() -> LaunchEnv {
    LaunchEnv {
        vars: [("PATH".to_string(), "/usr/bin:/bin".to_string())]
            .into_iter()
            .collect(),
        sandbox_scope_id: "probe-scope".to_string(),
    }
}

/// `leaks` — values from the auth-status fixture and the probe stderr
/// that must never appear in a ProbeResult or an error.
const LEAKS: &[&str] = &[
    "operator-probe@example.com",
    "Example Probe Org",
    "00000000-0000-4000-8000-00000000cafe",
    "/home/operator",
    "max",
];

/// `assertNoLeak` — no account, organization, UUID, home path or model
/// detail may surface in a result or error.
fn assert_no_leak(res: &central_harness::port::ProbeResult, err: Option<&Failure>) {
    let mut text = format!("{res:?}");
    if let Some(e) = err {
        text.push(' ');
        text.push_str(&format!("{e}"));
    }
    for leak in LEAKS {
        assert!(!text.contains(leak), "probe leaked {leak:?}: {text}");
    }
}

/// `cumulative` — a session-cumulative, estimated usage report.
fn cumulative(
    tokens_in: i64,
    tokens_out: i64,
    cache_read: i64,
    cache_write: i64,
    cost: i64,
) -> Usage {
    Usage {
        tokens_in,
        tokens_out,
        cache_read,
        cache_write,
        cost_micro_usd: cost,
        scope: UsageScope::SessionCumulative,
        estimated: true,
    }
}

/// `requireMonotonic` — no report may lower a counter of the one before
/// it; the domain's rule for session_cumulative reports.
fn require_monotonic(reports: &[Usage]) {
    for (i, w) in reports.windows(2).enumerate() {
        let (a, b) = (w[0], w[1]);
        assert!(
            b.tokens_in >= a.tokens_in
                && b.tokens_out >= a.tokens_out
                && b.cache_read >= a.cache_read
                && b.cache_write >= a.cache_write
                && b.cost_micro_usd >= a.cost_micro_usd,
            "usage report {} lowers a counter: {b:?} after {a:?}",
            i + 1
        );
    }
}

/// `collect` with upstream's `allowEvery`/`denyEvery`: every bridged
/// request is answered between event pulls (the `on` callback is sync,
/// so the answer cannot be awaited inside it).
async fn collect_answering(s: &Arc<dyn Session>, allow: bool) -> Vec<Event> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout_at(deadline, s.next_event())
            .await
            .expect("timed out collecting events")
        {
            Some(e) => {
                e.validate().expect("invalid event");
                assert_eq!(e.seq as usize, out.len() + 1, "seq");
                if let Some(EventPayload::PermissionRequested(p)) = &e.payload {
                    let digest: [u8; 32] = Sha256::digest(&p.input).into();
                    s.respond_permission(PermissionDecision {
                        request_id: p.request_id.clone(),
                        allow,
                        option_id: String::new(),
                        decided_by: "operator".to_string(),
                        input_sha256: if allow { digest } else { [0; 32] },
                    })
                    .await
                    .expect("respond");
                }
                out.push(e);
            }
            None => return out,
        }
    }
}

/// `line` — one hand-made frame as an NDJSON line.
fn line(v: Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(&v).unwrap();
    b.push(b'\n');
    b
}

/// `assistantFrame` — a hand-made assistant frame with one text block.
/// `None` id/usage leaves the member out; `with_parent` false leaves
/// `parent_tool_use_id` out (the main thread).
fn assistant_frame(
    id: Option<Value>,
    usage: Option<Value>,
    parent: Option<Value>,
    with_parent: bool,
) -> Vec<u8> {
    let mut message = serde_json::json!({
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": "working"}],
    });
    if let Some(id) = id {
        message["id"] = id;
    }
    if let Some(u) = usage {
        message["usage"] = u;
    }
    let mut frame = serde_json::json!({
        "type": "assistant",
        "message": message,
        "session_id": SESSION_ID,
    });
    if with_parent {
        frame["parent_tool_use_id"] = parent.unwrap_or(Value::Null);
    }
    line(frame)
}

/// `tokens` — a message usage object.
fn tokens(input: i64, output: i64, cache_write: i64, cache_read: i64) -> Value {
    serde_json::json!({
        "input_tokens": input,
        "output_tokens": output,
        "cache_creation_input_tokens": cache_write,
        "cache_read_input_tokens": cache_read,
    })
}

/// `resultFrame` — the success fixture's result with the given turn
/// usage, cumulative cost and queued turn count.
fn result_frame(usage: Value, cost_usd: f64, queued: i64) -> Vec<u8> {
    let mut r: Value =
        serde_json::from_slice(&fixture_line(&fixture("success.ndjson"), "result", ""))
            .expect("result line");
    r["usage"] = usage;
    r["total_cost_usd"] = serde_json::json!(cost_usd);
    r["queued_turn_count"] = serde_json::json!(queued);
    line(r)
}

/// `subagentFrame` — an assistant text block from a subagent: its
/// parent_tool_use_id names the Task tool call that spawned it.
const SUBAGENT_FRAME: &[u8] = b"{\"type\":\"assistant\",\"parent_tool_use_id\":\"toolu_subagent_1\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"SUBAGENT\"}]},\"session_id\":\"0192f000-0000-7000-8000-000000000001\"}\n";

/// `queuedTurnsFixture` — the real bridge-allow transcript preceded by
/// an earlier turn's result that reports one queued turn still to run.
/// The earlier result is an api_error (so a terminal mapped from it
/// would be Failed), with that turn's own, smaller usage and the
/// cumulative cost `first_cost_usd`.
fn queued_turns_fixture(first_cost_usd: f64) -> Vec<u8> {
    let fixture = fixture("bridge-allow.ndjson");
    let i = result_offset(&fixture);
    let end = i + fixture[i..]
        .iter()
        .position(|b| *b == b'\n')
        .expect("result line end");
    let mut first: Value = serde_json::from_slice(&fixture[i..end]).expect("result");
    let mut last: Value = serde_json::from_slice(&fixture[i..end]).expect("result");
    assert!(
        first["queued_turn_count"] == 0 && first["result_index"] == 0,
        "captured result lacks the queue fields: {first}"
    );
    first["queued_turn_count"] = serde_json::json!(1);
    first["total_cost_usd"] = serde_json::json!(first_cost_usd);
    first["usage"] = serde_json::json!({
        "input_tokens": 5,
        "output_tokens": 7,
        "cache_read_input_tokens": 100,
        "cache_creation_input_tokens": 200,
    });
    first["is_error"] = serde_json::json!(true);
    first["terminal_reason"] = serde_json::json!("api_error");
    last["result_index"] = serde_json::json!(1);
    let first_line = serde_json::to_string(&first).unwrap();
    let last_line = serde_json::to_string(&last).unwrap();
    // The earlier turn's result goes right before the second turn's
    // first assistant frame.
    let a = fixture
        .windows(b"{\"type\":\"assistant\"".len())
        .position(|w| w == b"{\"type\":\"assistant\"")
        .expect("assistant frame");
    assert!(a <= i, "no assistant frame before the result");
    let mut out = fixture[..a].to_vec();
    out.extend_from_slice(first_line.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&fixture[a..i]);
    out.extend_from_slice(last_line.as_bytes());
    out.extend_from_slice(&fixture[end..]);
    out
}

/// `interruptedQueueFixture` — the operator interrupts the first turn,
/// whose result reports a queued turn left; the queued turn then ends
/// in an unrelated error_during_execution. When `acked`, the harness
/// acknowledges the interrupt before the first result.
fn interrupted_queue_fixture(acked: bool) -> Vec<u8> {
    let fixture = fixture("success.ndjson");
    let i = result_offset(&fixture);
    let result = &fixture[i..];
    let first_result = mutate_result(result, |r| {
        r.insert("subtype".to_string(), "error_during_execution".into());
        r.insert("is_error".to_string(), true.into());
        r.insert("terminal_reason".to_string(), "aborted_streaming".into());
        r.insert("queued_turn_count".to_string(), 1.into());
        r.insert("result_index".to_string(), 0.into());
    });
    let last_result = mutate_result(result, |r| {
        r.insert("subtype".to_string(), "error_during_execution".into());
        r.insert("is_error".to_string(), true.into());
        r.insert("terminal_reason".to_string(), "something_new".into());
        r.insert("queued_turn_count".to_string(), 0.into());
        r.insert("result_index".to_string(), 1.into());
    });
    let mut out = fixture[..i].to_vec();
    out.extend_from_slice(b"{\"central_fixture\":\"await\",\"request\":\"interrupt\"}\n");
    if acked {
        out.extend_from_slice(b"{\"type\":\"control_response\",\"response\":{\"subtype\":\"success\",\"request_id\":\"central:interrupt-id\",\"response\":{\"still_queued\":[]}}}\n");
    }
    out.extend_from_slice(&first_result);
    out.extend_from_slice(&last_result);
    out
}

/// `startStuckStdin` — a session whose harness reads the initialize
/// request and the prompt, then never reads stdin again, so the next
/// write backpressures (upstream `io.Pipe`).
async fn start_stuck_stdin() -> (Arc<dyn Session>, Arc<ScriptedLauncher>) {
    let tr = Transcript::default();
    let read = Arc::new(Notify::new());
    let read2 = read.clone();
    let tr2 = tr.clone();
    let l = ScriptedLauncher::new(Box::new(move |p: Arc<ScriptedProcess>| {
        let tr3 = tr2.clone();
        let read3 = read2.clone();
        Box::pin(async move {
            let tr4 = tr3.clone();
            let rx = p.take_stdin_rx();
            tokio::spawn(async move { tr4.read(rx).await });
            if !tr3.await_count(2).await {
                p.exit(ExitStatus {
                    code: 1,
                    signaled: false,
                });
                return;
            }
            // The harness stopped reading: writes now backpressure.
            p.set_stdin_blocking(true);
            read3.notify_one();
            p.exited_wait().await;
        })
    }));
    let a = new_adapter(l.clone());
    let s: Arc<dyn Session> = Arc::from(
        a.start(start_spec(PermissionPolicy::Bridge))
            .await
            .expect("start"),
    );
    tokio::time::timeout(Duration::from_secs(5), read.notified())
        .await
        .expect("harness never read the prompt");
    (s, l)
}

// =====================================================================
// probe_test.go — the four probe scenarios against the three fixtures
// =====================================================================

/// `TestProbeLoggedIn` — the logged-in fixture yields the pinned
/// version, authenticated, the claude.ai detail; both probes run
/// through the launcher in the probe workdir under the probe scope
/// with only the given env.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_logged_in() {
    let l = ScriptedLauncher::unscripted();
    l.set_auth(
        &String::from_utf8_lossy(&fixture("auth-status-logged-in.json")),
        0,
    );
    let a = new_adapter(l.clone());
    let res = a.probe(probe_env()).await.expect("probe");
    assert_no_leak(&res, None);
    let want = central_harness::port::ProbeResult {
        harness_version: "2.1.283".to_string(),
        authenticated: true,
        detail: "auth method: claude.ai".to_string(),
    };
    assert_eq!(res, want);
    // Both probes ran through the launcher, in the probe workdir and
    // the given scope, with the env copied and nothing else.
    let launches = l.launches();
    assert_eq!(launches.len(), 2, "{launches:?}");
    for (i, want_args) in [["--version"].as_slice(), ["auth", "status"].as_slice()]
        .iter()
        .enumerate()
    {
        let got = &launches[i];
        assert_eq!(got.program, "claude");
        assert_eq!(got.args.as_slice(), *want_args, "launch {i}");
        assert_eq!(got.work_dir, "/probe");
        assert_eq!(got.scope_id, "probe-scope");
        assert_eq!(got.env.len(), 1);
        assert_eq!(
            got.env.get("PATH").map(String::as_str),
            Some("/usr/bin:/bin")
        );
    }
}

/// `TestProbeLoggedOutAndVersionMismatch` — a logged-out fixture plus
/// a version other than the pinned one reports both facts, still Ok.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_logged_out_and_version_mismatch() {
    let l = ScriptedLauncher::unscripted();
    l.set_auth(
        &String::from_utf8_lossy(&fixture("auth-status-logged-out.json")),
        1,
    );
    l.set_version("2.2.0 (Claude Code)\n");
    let a = new_adapter(l);
    let res = a.probe(probe_env()).await.expect("probe");
    assert!(!res.authenticated);
    assert_eq!(res.harness_version, "2.2.0");
    assert_eq!(
        res.detail,
        "auth method: none; not logged in; version 2.2.0 differs from pinned 2.1.283 (Start refuses)"
    );
}

/// `TestProbeCapsAndNeverCopiesOutput` — oversized or unexpected output
/// is an error that carries none of the output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_caps_and_never_copies_output() {
    let big = format!(
        "{{\"loggedIn\":true,\"authMethod\":\"claude.ai\",\"email\":\"operator-probe@example.com\",\"pad\":\"{}\"}}",
        "x".repeat(70 << 10)
    );
    let cases: [(&str, &str, &str); 5] = [
        ("auth over cap", "2.1.283 (Claude Code)\n", big.as_str()),
        (
            "auth not json",
            "2.1.283 (Claude Code)\n",
            "Logged in as operator-probe@example.com (Example Probe Org)\n",
        ),
        (
            "auth no loggedIn",
            "2.1.283 (Claude Code)\n",
            "{\"email\":\"operator-probe@example.com\"}",
        ),
        (
            "version not exact",
            "2.1.283 (Claude Code) operator-probe@example.com\n",
            "",
        ),
        (
            "version over cap",
            &"operator-probe@example.com ".repeat(3000),
            "",
        ),
    ];
    for (name, version, auth) in cases {
        let l = ScriptedLauncher::unscripted();
        l.set_version(version);
        l.set_auth(auth, 0);
        let a = new_adapter(l);
        let (res, err) = match a.probe(probe_env()).await {
            Ok(res) => (res, None),
            Err(e) => (central_harness::port::ProbeResult::default(), Some(e)),
        };
        let err = err.unwrap_or_else(|| unreachable!("{name}: probe succeeded with {res:?}"));
        assert!(
            is_code(&err, claudecode::codes::UNEXPECTED_PROBE_OUTPUT),
            "{name}: err = {err}"
        );
        assert_no_leak(&res, Some(&err));
        assert!(
            !res.authenticated && res.detail.is_empty(),
            "{name}: {res:?}"
        );
    }
}

/// `TestProbeRefusals` — missing/unsafe PATH, a credential env name and
/// a missing sandbox scope are refused before any launch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_refusals() {
    let a = new_adapter(ScriptedLauncher::unscripted());
    let mut env = probe_env();
    env.vars.remove("PATH");
    let err = a
        .probe(env)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("missing PATH succeeded"));
    assert!(is_code(&err, claudecode::codes::PATH_REQUIRED), "{err}");

    for path in UNSAFE_PATHS {
        let mut env = probe_env();
        env.vars.insert("PATH".to_string(), path.to_string());
        let err = a
            .probe(env)
            .await
            .err()
            .unwrap_or_else(|| unreachable!("unsafe PATH succeeded"));
        assert!(
            is_code(&err, claudecode::codes::PATH_REQUIRED),
            "PATH {path:?}: {err}"
        );
        assert!(
            path.len() <= 1 || !err.message().contains(path),
            "PATH {path:?} leaked into {err}"
        );
    }

    let mut env = probe_env();
    env.vars
        .insert("github_token".to_string(), "ghp_secret".to_string());
    let err = a
        .probe(env)
        .await
        .err()
        .unwrap_or_else(|| unreachable!("credential env succeeded"));
    assert!(
        is_code(&err, central_harness::domain::codes::FORBIDDEN_LAUNCH_ENV),
        "{err}"
    );
    assert!(!err.message().contains("ghp_secret"), "{err}");

    let mut env = probe_env();
    env.sandbox_scope_id.clear();
    assert!(
        a.probe(env).await.is_err(),
        "probe without a scope succeeded"
    );
}

// =====================================================================
// claudecode_test.go — identity, reason vocabulary, capabilities
// =====================================================================

/// `TestAdapterIdentity` — kind, capabilities, env extras; `new`
/// without a launcher is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adapter_identity() {
    let a = new_adapter(ScriptedLauncher::unscripted());
    assert_eq!(a.kind().as_str(), "claude-code");
    assert_eq!(a.capabilities(), claudecode::capabilities());
    assert!(a.env_extras().is_empty());
    assert!(
        ClaudeCode::new(Config::default()).is_err(),
        "New without a launcher succeeded"
    );
}

/// `TestReasonVocabularyIsPinned` — Terminal.Reason only ever carries
/// one of these fixed strings, never harness text.
#[test]
fn reason_vocabulary_is_pinned() {
    let want: &[&str] = &[
        "harness_not_authenticated",
        "harness_api_error",
        "harness_aborted",
        "harness_exited_without_result",
        "harness_session_mismatch",
        "harness_protocol_error",
        "harness_max_turns",
        "harness_budget",
        "harness_policy_mismatch",
        "harness_untrusted_project_config",
        "permission_bridge_unavailable",
    ];
    assert_eq!(claudecode::reasons(), want);
    let consts = [
        claudecode::reasons::HARNESS_NOT_AUTHENTICATED,
        claudecode::reasons::HARNESS_API_ERROR,
        claudecode::reasons::HARNESS_ABORTED,
        claudecode::reasons::HARNESS_EXITED_WITHOUT_RESULT,
        claudecode::reasons::HARNESS_SESSION_MISMATCH,
        claudecode::reasons::HARNESS_PROTOCOL_ERROR,
        claudecode::reasons::HARNESS_MAX_TURNS,
        claudecode::reasons::HARNESS_BUDGET,
        claudecode::reasons::HARNESS_POLICY_MISMATCH,
        claudecode::reasons::HARNESS_UNTRUSTED_PROJECT_CONFIG,
        claudecode::reasons::PERMISSION_BRIDGE_UNAVAILABLE,
    ];
    assert_eq!(consts.as_slice(), want);
}

/// `TestCapabilitiesMatchDecision16` — the declared matrix.
#[test]
fn capabilities_match_decision16() {
    let got = claudecode::capabilities();
    assert!(got.streaming_input);
    assert!(got.interrupt);
    assert!(got.resume_by_id);
    assert!(got.preassign_session_id);
    assert!(got.permission_bridge);
    assert!(got.usage_tokens);
    assert!(got.cost_usd);
    assert_eq!(got.usage_scope, UsageScope::SessionCumulative);
    assert!(got.native_cost_limit);
    got.validate().expect("capabilities validate");
    assert_eq!(claudecode::KIND, "claude-code");
    assert_eq!(claudecode::DEFAULT_PINNED_VERSION, "2.1.283");
}

// =====================================================================
// session_test.go — the remaining upstream scenarios
// =====================================================================

/// `TestCanUseToolUnderNonBridgePolicyIsDeniedWithWarning` — under Deny
/// and AutoAllow a can_use_tool is never bridged: the adapter denies it
/// itself with a fixed warning, and the tool result reports Denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn can_use_tool_under_non_bridge_policy_denied_with_warning() {
    for (policy, mode) in [
        (PermissionPolicy::Deny, "dontAsk"),
        (PermissionPolicy::AutoAllow, "bypassPermissions"),
    ] {
        let fixture = with_mode(&fixture("bridge-allow.ndjson"), mode);
        let r = start_with(&fixture, start_spec(policy), PlayOpts::default()).await;
        let events = collect(&*r.session, |_| {}).await;
        let mut warnings = Vec::new();
        let mut result = None;
        for e in &events {
            match &e.payload {
                Some(EventPayload::Warning(w)) => warnings.push(w.message.clone()),
                Some(EventPayload::ToolResult(tr)) => result = Some(tr.clone()),
                Some(EventPayload::PermissionRequested(_)) => {
                    unreachable!("{policy} bridged a permission request")
                }
                _ => {}
            }
        }
        assert_eq!(warnings.len(), 1, "{policy}: warnings = {warnings:?}");
        assert!(
            warnings[0].contains("non-bridge policy"),
            "{policy}: warning = {:?}",
            warnings[0]
        );
        let result = result.unwrap_or_else(|| unreachable!("{policy}: no tool result"));
        assert_eq!(result.status, ToolStatus::Denied);
        let lines = r.tr.all();
        assert_eq!(lines.len(), 3, "{policy}: written = {lines:?}");
        assert!(lines[2].contains(r#""behavior":"deny""#), "{lines:?}");
        assert!(!lines[2].contains("updatedInput"), "{lines:?}");
    }
}

/// `TestPermissionModeMismatchFailsClosed` — a harness whose init
/// reports a mode other than the policy's is killed before it acts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permission_mode_mismatch_fails_closed() {
    for (policy, fixture) in [
        // default, want dontAsk
        (PermissionPolicy::Deny, fixture("success.ndjson")),
        // want default
        (
            PermissionPolicy::Bridge,
            with_mode(&fixture("success.ndjson"), "bypassPermissions"),
        ),
        // want bypassPermissions
        (
            PermissionPolicy::AutoAllow,
            with_mode(&fixture("success.ndjson"), "acceptEdits"),
        ),
    ] {
        let r = start_with(&fixture, start_spec(policy), PlayOpts::default()).await;
        let events = collect(&*r.session, |_| {}).await;
        assert_eq!(
            kinds(&events),
            [EventKind::TerminalReported],
            "{policy}: kinds"
        );
        let t = terminal_of(&events);
        assert_eq!(t.status, TerminalStatus::Failed, "{policy}: {t:?}");
        assert_eq!(t.reason, claudecode::reasons::HARNESS_POLICY_MISMATCH);
        assert!(
            r.launcher.last_session().kill_count() > 0,
            "{policy}: process not killed"
        );
        assert!(
            r.session.session_ref().await.is_none(),
            "{policy}: mismatched session revealed"
        );
    }
}

/// `TestSessionIDMismatchFailsClosed` — the revealed session id is not
/// the attempt's: failed, killed (143), nothing revealed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_id_mismatch_fails_closed() {
    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.attempt = HarnessAttemptId::new();
    let r = start_with(&fixture("success.ndjson"), spec, PlayOpts::default()).await;
    let events = collect(&*r.session, |_| {}).await;
    assert_eq!(events.len(), 1, "{:?}", kinds(&events));
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_SESSION_MISMATCH);
    assert_eq!(exit_code(&t), 143);
}

/// `TestResultTerminalMappingEndToEnd` — the §6 rows that need a wire
/// round-trip: api_error, max_turns, budget, unknown error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_terminal_mapping_end_to_end() {
    for (subtype, reason, status, want_reason) in [
        (
            "success",
            "api_error",
            TerminalStatus::Failed,
            claudecode::reasons::HARNESS_API_ERROR,
        ),
        (
            "error_max_turns",
            "max_turns",
            TerminalStatus::MaxTurns,
            claudecode::reasons::HARNESS_MAX_TURNS,
        ),
        (
            "error_max_budget_usd",
            "budget",
            TerminalStatus::Budget,
            claudecode::reasons::HARNESS_BUDGET,
        ),
        (
            "error_during_execution",
            "something_new",
            TerminalStatus::Failed,
            claudecode::reasons::HARNESS_API_ERROR,
        ),
    ] {
        let fixture = mutate_result(&fixture("success.ndjson"), |r| {
            r.insert("subtype".to_string(), subtype.into());
            r.insert("is_error".to_string(), true.into());
            r.insert("terminal_reason".to_string(), reason.into());
        });
        let r = start_with(
            &fixture,
            start_spec(PermissionPolicy::Bridge),
            PlayOpts {
                exit_code: 1,
                ..PlayOpts::default()
            },
        )
        .await;
        let t = terminal_of(&collect(&*r.session, |_| {}).await);
        assert_eq!(t.status, status, "{subtype}: {t:?}");
        assert_eq!(t.reason, want_reason, "{subtype}: {t:?}");
    }
}

/// `TestQueuedTurnsEndOnlyOnTheLastResult` — every result reports
/// usage, but a result with a queued turn left neither closes stdin nor
/// drops pending permissions; the terminal is mapped from the last
/// result. Each result's tokens are that turn's own, so the reports
/// carry their running sums, and the cost is the latest cumulative one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_turns_end_only_on_the_last_result() {
    let r = start_with(
        &queued_turns_fixture(0.01),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect_answering(&r.session, true).await;
    let want = [
        // The first result, then each main-thread message's live report
        // (harness phase 3l decision 3).
        EventKind::SessionStarted,
        EventKind::UsageReport,
        EventKind::UsageReport,
        EventKind::Reasoning,
        EventKind::ToolCall,
        EventKind::PermissionRequested,
        EventKind::PermissionResolved,
        EventKind::ToolResult,
        EventKind::UsageReport,
        EventKind::Reasoning,
        EventKind::Message,
        // Only the last result (nothing queued) adds its text.
        EventKind::UsageReport,
        EventKind::Message,
        EventKind::TerminalReported,
    ];
    assert_eq!(kinds(&events), want.as_slice(), "kinds");
    let usage_at = |i: usize| match &events[i].payload {
        Some(EventPayload::UsageReport(u)) => u.usage,
        other => unreachable!("events[{i}] = {other:?}"),
    };
    let first = usage_at(1);
    let last = usage_at(11);
    let want_first = cumulative(5, 7, 100, 200, 10000);
    // The live reports never lower what the first result reported: its
    // output tokens (7) and cache reads (100) and its cost are carried.
    let want_live = [
        cumulative(10, 7, 100, 34434, 10000),
        cumulative(18, 7, 100, 35532, 10000),
    ];
    // The last report is the two results' sum, not added on the live
    // figure (harness phase 3l decision 4): 5 + 18 tokens in.
    let want_last = cumulative(5 + 18, 7 + 205, 100 + 63842, 200 + 35532, 78491);
    let live = [usage_at(2), usage_at(8)];
    assert_eq!(first, want_first, "first report");
    assert_eq!(live, want_live, "live reports");
    assert_eq!(last, want_last, "last report");
    assert_eq!(fold_usage(&usage_reports(&events)), want_last);
    match &events[7].payload {
        Some(EventPayload::ToolResult(res)) => assert_eq!(res.status, ToolStatus::Ok),
        other => unreachable!("tool result = {other:?}"),
    }
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Succeeded);
    assert!(t.reason.is_empty());
    assert_eq!(exit_code(&t), 0);
    // initialize, the prompt, and the allow answer written after the
    // first result: stdin stayed open until the last one.
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(r.tr.frames()[2]["type"], "control_response");
}

/// `TestQueuedResultCostNeverDecreases` — a later result whose
/// cumulative cost is lower than one already reported (a crash result
/// or /clear) never lowers the reported cost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_result_cost_never_decreases() {
    let r = start_with(
        &queued_turns_fixture(0.1),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect_answering(&r.session, true).await;
    // The first result, the two live reports (which carry its cost) and
    // the last result (harness phase 3l decision 4).
    let reports = usage_reports(&events);
    assert_eq!(reports.len(), 4, "{reports:?}");
    assert_eq!(reports[3].tokens_out, 7 + 205);
    for (i, u) in reports.iter().enumerate() {
        assert_eq!(u.cost_micro_usd, 100_000, "report {i} cost");
    }
    assert_eq!(fold_usage(&reports), reports[3]);
}

/// `TestEOFAfterQueuedResultFails` — a harness that exits after a
/// result with a queued turn left, without the last result, has not
/// finished the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eof_after_queued_result_fails() {
    let fixture = mutate_result(&fixture("success.ndjson"), |r| {
        r.insert("queued_turn_count".to_string(), 1.into());
    });
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts {
            exit_code: 1,
            end_without_result: true,
        },
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    // The message's live report and the queued result's.
    assert_eq!(usage_reports(&events).len(), 2);
    // The result's text is emitted only for the last result, never for
    // an earlier one that leaves a turn queued.
    let (texts, after_usage) = messages_of(&events);
    assert!(!after_usage && texts == ["OK"], "messages = {texts:?}");
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_EXITED_WITHOUT_RESULT);
    assert_eq!(exit_code(&t), 1);
}

/// `TestCanUseToolAfterLastResultIsIgnored` — a permission request that
/// arrives after the last result is neither answered nor bridged,
/// because stdin is already closing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn can_use_tool_after_last_result_is_ignored() {
    let mut fixture = fixture("success.ndjson");
    fixture.extend_from_slice(
        b"{\"type\":\"control_request\",\"request_id\":\"late-1\",\"request\":{\"subtype\":\"can_use_tool\",\"tool_name\":\"Bash\",\"input\":{\"command\":\"ls\"},\"tool_use_id\":\"toolu_late\"}}\n",
    );
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let want = [
        EventKind::SessionStarted,
        EventKind::UsageReport,
        EventKind::Reasoning,
        EventKind::Message,
        EventKind::UsageReport,
        EventKind::Message,
        EventKind::TerminalReported,
    ];
    assert_eq!(kinds(&events), want.as_slice(), "kinds");
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    assert_eq!(r.tr.all().len(), 2, "{:?}", r.tr.all());
}

/// `TestInterruptIsSpentOnTheTurnItAborted` — an acknowledged interrupt
/// ends with the queued turn's result it aborted, so a later turn's
/// unrelated error_during_execution maps as a failure, not Interrupted.
/// An interrupt not yet acknowledged at that result still applies to
/// the next turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupt_is_spent_on_the_turn_it_aborted() {
    for (acked, status, reason) in [
        (
            true,
            TerminalStatus::Failed,
            claudecode::reasons::HARNESS_API_ERROR,
        ),
        (
            false,
            TerminalStatus::Interrupted,
            claudecode::reasons::HARNESS_ABORTED,
        ),
    ] {
        let r = start_with(
            &interrupted_queue_fixture(acked),
            start_spec(PermissionPolicy::Bridge),
            PlayOpts {
                exit_code: 1,
                ..PlayOpts::default()
            },
        )
        .await;
        let mut events = Vec::new();
        let mut interrupted = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
            .await
            .expect("timed out collecting events")
        {
            e.validate().expect("invalid event");
            if matches!(&e.payload, Some(EventPayload::SessionStarted(_))) && !interrupted {
                interrupted = true;
                r.session.interrupt().await.expect("interrupt");
            }
            events.push(e);
        }
        // The message's live report (phase 3l), then both results.
        assert_eq!(usage_reports(&events).len(), 3, "acked={acked}");
        let t = terminal_of(&events);
        assert_eq!(t.status, status, "acked={acked}: {t:?}");
        assert_eq!(t.reason, reason, "acked={acked}: {t:?}");
    }
}

/// `TestResultWithoutQueueFieldsEndsTheSession` — a result that does
/// not carry queued_turn_count still ends the session, as before
/// 2.1.283 added it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_without_queue_fields_ends_the_session() {
    let fixture = mutate_result(&fixture("success.ndjson"), |r| {
        r.remove("queued_turn_count");
        r.remove("result_index");
    });
    assert!(
        !String::from_utf8_lossy(&fixture).contains("queued_turn_count"),
        "fixture still carries queued_turn_count"
    );
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    // The message's live report (phase 3l) and the result's.
    assert_eq!(usage_reports(&events).len(), 2);
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Succeeded);
    assert_eq!(exit_code(&t), 0);
}

/// `TestUnsupportedControlRequestIsRefused` — a control request with an
/// unsupported subtype gets a fixed error response and a warning; the
/// run succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unsupported_control_request_is_refused() {
    let base = fixture("success.ndjson");
    let hook = b"{\"type\":\"control_request\",\"request_id\":\"hook-1\",\"request\":{\"subtype\":\"hook_callback\",\"callback_id\":\"x\"}}\n".as_slice();
    let i = result_offset(&base);
    let mut fixture = base[..i].to_vec();
    fixture.extend_from_slice(hook);
    fixture.extend_from_slice(&base[i..]);
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let warned = events.iter().any(|e| {
        matches!(&e.payload, Some(EventPayload::Warning(w)) if w.message.contains("unsupported"))
    });
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(
        lines[2],
        r#"{"type":"control_response","response":{"subtype":"error","request_id":"hook-1","error":"unsupported control request"}}"#
    );
    assert!(warned, "no unsupported warning");
}

/// `TestMalformedControlRequestWithIDIsAnswered` — a control_request
/// whose body does not decode but carries a request_id is still
/// answered, so the harness never waits on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_control_request_with_id_is_answered() {
    let base = fixture("success.ndjson");
    let bad =
        b"{\"type\":\"control_request\",\"request_id\":\"bad-1\",\"request\":\"not an object\"}\n"
            .as_slice();
    let i = result_offset(&base);
    let mut fixture = base[..i].to_vec();
    fixture.extend_from_slice(bad);
    fixture.extend_from_slice(&base[i..]);
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let warned = events.iter().any(|e| {
        matches!(&e.payload, Some(EventPayload::Warning(w))
            if w.message == "malformed harness frame" && String::from_utf8_lossy(&e.raw).contains("bad-1"))
    });
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(
        lines[2],
        r#"{"type":"control_response","response":{"subtype":"error","request_id":"bad-1","error":"unsupported control request"}}"#
    );
    assert!(warned, "no malformed warning");
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestPolicyDenyAnswerWriteFailureWarns` — a policy-deny answer that
/// cannot be written is reported as a fixed warning ahead of the
/// terminal event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_deny_answer_write_failure_warns() {
    let fixture = with_mode(&fixture("bridge-allow.ndjson"), "dontAsk");
    let l = ScriptedLauncher::new(Box::new(move |p: Arc<ScriptedProcess>| {
        let fixture = fixture.clone();
        Box::pin(async move {
            // Read the initialize request and the prompt, then break
            // stdin like upstream's `stdinR.CloseWithError`.
            let rx = p.take_stdin_rx();
            let tr = Transcript::default();
            let tr2 = tr.clone();
            tokio::spawn(async move { tr2.read(rx).await });
            if !tr.await_count(2).await {
                p.exit(ExitStatus {
                    code: 1,
                    signaled: false,
                });
                return;
            }
            p.break_stdin();
            for line in fixture.split(|b| *b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if p.emit_line(line).await.is_err() {
                    return;
                }
                if String::from_utf8_lossy(line).contains("\"type\":\"control_request\"") {
                    break;
                }
            }
            p.exit(ExitStatus {
                code: 1,
                signaled: false,
            });
        })
    }));
    let a = new_adapter(l);
    let s = a
        .start(start_spec(PermissionPolicy::Deny))
        .await
        .expect("start");
    let events = collect(&*s, |_| {}).await;
    let warnings: Vec<&Event> = events
        .iter()
        .filter(|e| matches!(&e.payload, Some(EventPayload::Warning(_))))
        .collect();
    assert_eq!(warnings.len(), 2, "warnings = {warnings:?}");
    match &warnings[1].payload {
        Some(EventPayload::Warning(w)) => {
            assert_eq!(w.message, "answering a harness control request failed");
            assert!(String::from_utf8_lossy(&warnings[1].raw).contains("can_use_tool"));
        }
        other => unreachable!("warning = {other:?}"),
    }
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_EXITED_WITHOUT_RESULT);
}

/// `TestKillIsNotBlockedByAStuckStdinWrite` — a Send stuck writing to a
/// harness that stopped reading stdin delays neither Kill nor its kill
/// ladder, and the kill fails the stuck write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_is_not_blocked_by_a_stuck_stdin_write() {
    let (s, l) = start_stuck_stdin().await;
    let s2 = s.clone();
    let send = tokio::spawn(async move {
        s2.send(OperatorInput {
            text: "x".to_string(),
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!send.is_finished(), "send to an unread stdin returned");
    let s3 = s.clone();
    tokio::time::timeout(Duration::from_secs(2), async move { s3.kill().await })
        .await
        .expect("kill blocked behind a stuck stdin write")
        .expect("kill");
    assert!(l.last_session().kill_count() > 0, "process was not killed");
    let send_result = tokio::time::timeout(Duration::from_secs(5), send)
        .await
        .expect("stuck send outlived the kill")
        .expect("send task");
    assert!(send_result.is_err(), "stuck send succeeded after the kill");
    let t = terminal_of(&collect(&*s, |_| {}).await);
    assert_eq!(t.status, TerminalStatus::Killed);
}

/// `TestSendStuckOnStdinHonoursCtx` — a Send waiting on a stuck write
/// finishes (dropped under a timeout) without wedging the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_stuck_on_stdin_can_be_dropped() {
    let (s, _l) = start_stuck_stdin().await;
    // Dropping the future mid-write must release the write path:
    // upstream's ctx cancellation.
    let res = tokio::time::timeout(
        Duration::from_millis(100),
        s.send(OperatorInput {
            text: "x".to_string(),
        }),
    )
    .await;
    assert!(res.is_err(), "send to an unread stdin returned");
    s.kill().await.expect("kill");
    let _ = collect(&*s, |_| {}).await;
}

/// `TestSendWritesOperatorInput` — a follow-up user frame in the exact
/// outgoing shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_writes_operator_input() {
    let r = start_with(
        &fixture("bridge-allow.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
        .await
        .expect("timed out collecting events")
    {
        e.validate().expect("invalid event");
        if let Some(EventPayload::PermissionRequested(p)) = &e.payload {
            r.session
                .send(OperatorInput {
                    text: "also say hi".to_string(),
                })
                .await
                .expect("send");
            let digest: [u8; 32] = Sha256::digest(&p.input).into();
            let _ = r
                .session
                .respond_permission(PermissionDecision {
                    request_id: p.request_id.clone(),
                    allow: true,
                    option_id: String::new(),
                    decided_by: String::new(),
                    input_sha256: digest,
                })
                .await;
        }
        events.push(e);
    }
    let lines = r.tr.all();
    assert!(lines.len() >= 3, "{lines:?}");
    assert_eq!(
        lines[2],
        r#"{"type":"user","message":{"role":"user","content":"also say hi"}}"#
    );
}

/// `TestRespondPermissionUnknownRequestWritesNothing` — an answer for a
/// request id the adapter never bridged writes no frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn respond_permission_unknown_request_writes_nothing() {
    let r = start_with(
        &fixture("bridge-allow.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
        .await
        .expect("timed out collecting events")
    {
        if let Some(EventPayload::PermissionRequested(p)) = &e.payload {
            let err = r
                .session
                .respond_permission(PermissionDecision {
                    request_id: format!("not-{}", p.request_id),
                    allow: true,
                    option_id: String::new(),
                    decided_by: String::new(),
                    input_sha256: [0; 32],
                })
                .await
                .err()
                .unwrap_or_else(|| unreachable!("unknown id succeeded"));
            assert!(
                is_code(&err, central_harness::port::codes::NO_PENDING_PERMISSION),
                "{err}"
            );
            assert_eq!(r.tr.count(), 2, "a refused answer wrote a frame");
            let digest: [u8; 32] = Sha256::digest(&p.input).into();
            let _ = r
                .session
                .respond_permission(PermissionDecision {
                    request_id: p.request_id.clone(),
                    allow: true,
                    option_id: String::new(),
                    decided_by: String::new(),
                    input_sha256: digest,
                })
                .await;
        }
    }
}

/// `TestInitVersionMismatchFailsClosed` — the version the running
/// process reports in init must be the pinned one, not only the version
/// the separate pre-launch probe saw (security review S4).
/// AllowUnpinned lifts the check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_version_mismatch_fails_closed() {
    let fixture = replace_once(
        &fixture("success.ndjson"),
        br#""claude_code_version":"2.1.283""#,
        br#""claude_code_version":"2.1.284""#,
    );
    // Pinned: fail closed.
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    assert_eq!(kinds(&events), [EventKind::TerminalReported]);
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_PROTOCOL_ERROR);
    assert!(
        r.launcher.last_session().kill_count() > 0,
        "process not killed"
    );
    assert!(r.session.session_ref().await.is_none());
    // AllowUnpinned: the init's version is accepted.
    let tr = Transcript::default();
    let l = ScriptedLauncher::new(play_script(fixture.clone(), tr, PlayOpts::default()));
    let loose = ClaudeCode::new(Config {
        launcher: Some(l),
        allow_unpinned: true,
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .expect("loose adapter");
    let s = loose
        .start(start_spec(PermissionPolicy::Bridge))
        .await
        .expect("start");
    let events = collect(&*s, |_| {}).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestFramesBeforeInitFailClosed` — an assistant, user or result
/// frame, or a can_use_tool request, before a verified system/init
/// kills the process and ends failed/harness_protocol_error, reveals
/// nothing and answers nothing (technical review T-I3).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_before_init_fail_closed() {
    let success = fixture("success.ndjson");
    let bridge = fixture("bridge-allow.ndjson");
    let hook = fixture_line(&success, "system", "hook_started");
    let init_line = fixture_line(&success, "system", "init");
    for (name, line) in [
        ("assistant", fixture_line(&success, "assistant", "")),
        ("user", fixture_line(&bridge, "user", "")),
        ("result", fixture_line(&success, "result", "")),
        (
            "can_use_tool",
            fixture_line(&bridge, "control_request", "can_use_tool"),
        ),
    ] {
        // A valid init and result after the early frame must not rescue
        // the session.
        let fixture = [
            hook.as_slice(),
            line.as_slice(),
            init_line.as_slice(),
            fixture_line(&success, "result", "").as_slice(),
        ]
        .concat();
        let r = start_with(
            &fixture,
            start_spec(PermissionPolicy::Bridge),
            PlayOpts::default(),
        )
        .await;
        let events = collect(&*r.session, |_| {}).await;
        assert_eq!(kinds(&events), [EventKind::TerminalReported], "{name}");
        let t = terminal_of(&events);
        assert_eq!(t.status, TerminalStatus::Failed, "{name}: {t:?}");
        assert_eq!(t.reason, claudecode::reasons::HARNESS_PROTOCOL_ERROR);
        assert_eq!(exit_code(&t), 143, "{name}");
        assert!(
            r.launcher.last_session().kill_count() > 0,
            "{name}: process not killed"
        );
        assert!(
            r.session.session_ref().await.is_none(),
            "{name}: session revealed without init"
        );
        assert_eq!(
            r.tr.all().len(),
            2,
            "{name}: adapter answered a pre-init frame: {:?}",
            r.tr.all()
        );
    }
}

/// `TestWaitThenDrainDeliversEverything` — Wait returns without anyone
/// reading events; draining afterwards still yields every event in
/// order, then the close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wait_then_drain_delivers_everything() {
    let eager = start_with(
        &fixture("success.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let want = kinds(&collect(&*eager.session, |_| {}).await);

    let r = start_with(
        &fixture("success.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let t = wait_terminal(&*r.session).await;
    assert_eq!(t.status, TerminalStatus::Succeeded);
    let events = collect(&*r.session, |_| {}).await;
    assert_eq!(kinds(&events), want, "kinds after wait");
    assert_eq!(terminal_of(&events), t, "drained terminal vs wait");
}

/// `TestReconcileReportsScopeAliveOnly` — reconcile reports only
/// whether the attempt's scope is alive; no reattach, no terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconcile_reports_scope_alive_only() {
    let l = ScriptedLauncher::unscripted();
    l.set_alive("scope-live", true);
    let a = new_adapter(l);
    for (scope, want) in [("scope-live", true), ("scope-gone", false)] {
        let got = a
            .reconcile(ReconcileInput {
                attempt: HarnessAttemptId::new(),
                sandbox_scope_id: scope.to_string(),
                harness_session_id: FIXTURE_SESSION.to_string(),
                last_event_seq: 0,
            })
            .await
            .expect("reconcile");
        assert_eq!(got.scope_alive, want, "{scope}");
        assert!(
            got.reattached.is_none() && got.terminal.is_none(),
            "{scope}: {got:?}"
        );
    }
    let err = a
        .reconcile(ReconcileInput {
            attempt: HarnessAttemptId::new(),
            sandbox_scope_id: String::new(),
            harness_session_id: String::new(),
            last_event_seq: 0,
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("reconcile without a scope succeeded"));
    assert!(is_code(&err, claudecode::codes::INVALID_LAUNCH), "{err}");
}

// =====================================================================
// permission_bridge_test.go — bounds, echoes and fail-closed cases
// =====================================================================

/// `TestPermissionRequestedCarriesTheToolCallIDAndTheEchoedInput`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn permission_requested_carries_tool_call_id_and_echoed_input() {
    let r = start_with(
        &fixture("bridge-allow.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect_answering(&r.session, true).await;
    let requested = events
        .iter()
        .find_map(|e| match &e.payload {
            Some(EventPayload::PermissionRequested(p)) => Some(p.clone()),
            _ => None,
        })
        .expect("a permission request");
    let want_input = r#"{"command":"echo probe > probe.txt","description":"Create probe.txt with the text \"probe\""}"#;
    assert_eq!(requested.tool_call_id, "toolu_011r1UrbLM4eu7EYBqc2WYwD");
    assert_eq!(String::from_utf8_lossy(&requested.input), want_input);
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(
        lines[2].contains(&format!("\"updatedInput\":{want_input}}}")),
        "the allow did not echo exactly the emitted input: {lines:?}"
    );
}

/// `TestEmittedInputIsTheCompactFormTheAllowEchoes` — a spaced input is
/// emitted (and echoed) in compact form.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emitted_input_is_the_compact_form_the_allow_echoes() {
    // A `Value` would re-compact, so the spaced input is spliced into
    // the frame as raw bytes like upstream's `json.RawMessage`.
    let spaced = replace_once(
        &can_use_tool("", |req| {
            req.insert("input".to_string(), "central:spaced-input".into());
        }),
        b"\"central:spaced-input\"",
        br#"{ "command" : "ls  -la",  "n": [1, 2] }"#,
    );
    let r = start_with(
        &with_can_use_tool(&spaced),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect_answering(&r.session, true).await;
    let input = events
        .iter()
        .find_map(|e| match &e.payload {
            Some(EventPayload::PermissionRequested(p)) => Some(p.input.clone()),
            _ => None,
        })
        .expect("a permission request");
    assert_eq!(
        String::from_utf8_lossy(&input),
        r#"{"command":"ls  -la","n":[1,2]}"#
    );
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(
        lines[2].contains(r#""updatedInput":{"command":"ls  -la","n":[1,2]}}"#),
        "written = {lines:?}"
    );
}

/// `TestRespondPermissionRefusesAnAllowThatDoesNotBindTheInput` — an
/// allow whose digest is not the emitted input's is refused with
/// PERMISSION_BINDING and writes nothing; the request stays pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn respond_permission_refuses_an_allow_that_does_not_bind_the_input() {
    let r = start_with(
        &fixture("bridge-allow.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
        .await
        .expect("timed out collecting events")
    {
        if let Some(EventPayload::PermissionRequested(p)) = &e.payload {
            for (name, digest) in [
                ("zero", [0u8; 32]),
                (
                    "another input",
                    Sha256::digest(br#"{"command":"rm -rf /"}"#).into(),
                ),
                ("raw frame", Sha256::digest(&e.raw).into()),
            ] {
                let err = r
                    .session
                    .respond_permission(PermissionDecision {
                        request_id: p.request_id.clone(),
                        allow: true,
                        option_id: String::new(),
                        decided_by: String::new(),
                        input_sha256: digest,
                    })
                    .await
                    .err()
                    .unwrap_or_else(|| unreachable!("unbound allow succeeded"));
                assert!(
                    is_code(&err, central_harness::port::codes::PERMISSION_BINDING),
                    "{name} digest: {err}"
                );
                assert!(
                    !is_code(&err, central_harness::port::codes::NO_PENDING_PERMISSION),
                    "{name} digest consumed the request: {err}"
                );
            }
            assert_eq!(r.tr.all().len(), 2, "a refused allow wrote frames");
            // Still pending: the bound allow is accepted.
            let bound: [u8; 32] = Sha256::digest(&p.input).into();
            r.session
                .respond_permission(PermissionDecision {
                    request_id: p.request_id.clone(),
                    allow: true,
                    option_id: String::new(),
                    decided_by: String::new(),
                    input_sha256: bound,
                })
                .await
                .expect("bound allow");
        }
    }
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[2].contains(r#""behavior":"allow""#), "{lines:?}");
}

/// `TestADuplicatePendingRequestIDFailsClosedUnanswered` — a second
/// request reusing a pending id is a protocol error: fail closed, kill,
/// answer nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_pending_request_id_fails_closed_unanswered() {
    let init_line = fixture_line(&fixture("bridge-allow.ndjson"), "system", "init");
    let first = can_use_tool("dup-1", |_| {});
    let second = can_use_tool("dup-1", |req| {
        req.insert(
            "input".to_string(),
            serde_json::json!({"command": "rm -rf /"}),
        );
    });
    let r = start_raw(vec![init_line, first, second]).await;
    let mut requested = Vec::new();
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
        .await
        .expect("timed out collecting events")
    {
        e.validate().expect("invalid event");
        if let Some(EventPayload::PermissionRequested(p)) = &e.payload {
            requested.push(p.clone());
        }
        events.push(e);
    }
    assert_eq!(requested.len(), 1, "{requested:?}");
    assert!(
        String::from_utf8_lossy(&requested[0].input).contains("echo probe"),
        "{:?}",
        requested[0].input
    );
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::PERMISSION_BRIDGE_UNAVAILABLE);
    assert_eq!(
        r.tr.all().len(),
        2,
        "the adapter answered a duplicate request id: {:?}",
        r.tr.all()
    );
    let digest: [u8; 32] = Sha256::digest(&requested[0].input).into();
    let err = r
        .session
        .respond_permission(PermissionDecision {
            request_id: "dup-1".to_string(),
            allow: true,
            option_id: String::new(),
            decided_by: String::new(),
            input_sha256: digest,
        })
        .await
        .err()
        .unwrap_or_else(|| unreachable!("answer after the fail-closed stop succeeded"));
    assert!(
        is_code(&err, central_harness::port::codes::NO_PENDING_PERMISSION),
        "{err}"
    );
}

/// `TestOutOfBoundsPermissionRequestFieldsFailClosedUnanswered` — a
/// request id, tool call id, tool name or resource over its phase 3c
/// bound is a protocol error: never bridged, never answered, killed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn out_of_bounds_permission_request_fields_fail_closed_unanswered() {
    let init_line = fixture_line(&fixture("bridge-allow.ndjson"), "system", "init");
    let cases: [(&str, Vec<u8>); 6] = [
        ("request id", can_use_tool(&"r".repeat(513), |_| {})),
        (
            "tool call id",
            can_use_tool("", |q| {
                q.insert("tool_use_id".to_string(), "t".repeat(513).into());
            }),
        ),
        (
            "tool name length",
            can_use_tool("", |q| {
                q.insert("tool_name".to_string(), "n".repeat(257).into());
            }),
        ),
        (
            "tool name escape",
            can_use_tool("", |q| {
                q.insert("tool_name".to_string(), "Bash\u{1b}[2J".into());
            }),
        ),
        (
            "tool name utf8",
            can_use_tool("", |q| {
                q.insert("tool_name".to_string(), "Bash\u{202e}".into());
            }),
        ),
        (
            "resource size",
            can_use_tool("", |q| {
                q.insert(
                    "blocked_path".to_string(),
                    format!("/{}", "p".repeat(1024)).into(),
                );
            }),
        ),
    ];
    for (name, line) in cases {
        let r = start_raw(vec![init_line.clone(), line]).await;
        let events = collect(&*r.session, |_| {}).await;
        for e in &events {
            assert!(
                !matches!(
                    &e.payload,
                    Some(
                        EventPayload::PermissionRequested(_) | EventPayload::PermissionResolved(_)
                    )
                ),
                "{name}: an out-of-bounds request was bridged: {e:?}"
            );
        }
        let t = terminal_of(&events);
        assert_eq!(t.status, TerminalStatus::Failed, "{name}: {t:?}");
        assert_eq!(t.reason, claudecode::reasons::PERMISSION_BRIDGE_UNAVAILABLE);
        assert_eq!(
            r.tr.all().len(),
            2,
            "{name}: the adapter answered an out-of-bounds request: {:?}",
            r.tr.all()
        );
        assert!(
            r.launcher.last_session().kill_count() > 0,
            "{name}: process not killed"
        );
    }
}

/// `TestAtTheBridgeLimitRequestsAreBridged` — a harness-controlled
/// field exactly at its phase 3c bound is bridged like any other
/// request, never stopped or denied for size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_the_bridge_limit_requests_are_bridged() {
    use central_harness::approval::{
        MAX_PERMISSION_REQUEST_ID_BYTES, MAX_PERMISSION_RESOURCE_BYTES, MAX_TOOL_CALL_ID_BYTES,
        MAX_TOOL_NAME_BYTES,
    };
    let padding = "a".repeat(MAX_BRIDGED_INPUT_BYTES - "{\"a\":\"\"}".len());
    let input_line = can_use_tool("", |q| {
        q.insert("input".to_string(), "@@INPUT@@".into());
    });
    let input_line = replace_once(
        &input_line,
        b"\"@@INPUT@@\"",
        format!("{{\"a\":\"{padding}\"}}").as_bytes(),
    );
    let cases: [(&str, Vec<u8>); 5] = [
        (
            "request id",
            can_use_tool(&"r".repeat(MAX_PERMISSION_REQUEST_ID_BYTES), |_| {}),
        ),
        (
            "tool call id",
            can_use_tool("", |q| {
                q.insert(
                    "tool_use_id".to_string(),
                    "t".repeat(MAX_TOOL_CALL_ID_BYTES).into(),
                );
            }),
        ),
        (
            "tool name length",
            can_use_tool("", |q| {
                q.insert(
                    "tool_name".to_string(),
                    "n".repeat(MAX_TOOL_NAME_BYTES).into(),
                );
            }),
        ),
        (
            "resource size",
            can_use_tool("", |q| {
                q.insert(
                    "blocked_path".to_string(),
                    "p".repeat(MAX_PERMISSION_RESOURCE_BYTES).into(),
                );
            }),
        ),
        ("input size", input_line),
    ];
    for (name, line) in cases {
        let r = start_with(
            &with_can_use_tool(&line),
            start_spec(PermissionPolicy::Bridge),
            PlayOpts::default(),
        )
        .await;
        let events = collect_answering(&r.session, false).await;
        let bridged = events
            .iter()
            .any(|e| matches!(&e.payload, Some(EventPayload::PermissionRequested(_))));
        assert!(bridged, "{name}: an at-limit request was not bridged");
    }
}

/// `TestAnInputOverTheBridgeLimitIsDeniedAtOnce` — the deny is recorded
/// with the fixed input_too_large decider and written, never bridged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_over_the_bridge_limit_is_denied_at_once() {
    let huge = can_use_tool("big-1", |req| {
        req.insert(
            "input".to_string(),
            serde_json::json!({"command": "a".repeat(MAX_BRIDGED_INPUT_BYTES)}),
        );
    });
    let r = start_with(
        &with_can_use_tool(&huge),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let mut resolved = Vec::new();
    let mut result = None;
    let events = collect(&*r.session, |e| {
        assert!(
            !matches!(&e.payload, Some(EventPayload::PermissionRequested(_))),
            "an oversize input was bridged"
        );
    })
    .await;
    for e in &events {
        match &e.payload {
            Some(EventPayload::PermissionResolved(p)) => resolved.push(p.clone()),
            Some(EventPayload::ToolResult(p)) => result = Some(p.clone()),
            _ => {}
        }
    }
    assert_eq!(resolved.len(), 1, "{resolved:?}");
    assert_eq!(resolved[0].request_id, "big-1");
    assert_eq!(
        resolved[0].decision,
        central_harness::event::PermissionOutcome::Denied
    );
    assert_eq!(
        resolved[0].decided_by,
        central_harness::approval::DECIDED_BY_INPUT_TOO_LARGE
    );
    let result = result.expect("tool result");
    assert_eq!(result.status, ToolStatus::Denied);
    let lines = r.tr.all();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[2].contains(r#""behavior":"deny""#), "{lines:?}");
    assert!(!lines[2].contains("updatedInput"), "{lines:?}");
    assert!(lines[2].contains("too large"), "{lines:?}");
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestAnInputWithDuplicateKeysFailsClosedUnanswered` — a tool input
/// repeating an object key, at the top level or nested, is a protocol
/// error: never bridged, never answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_with_duplicate_keys_fails_closed_unanswered() {
    // The escaped-key case spells the second "command" with a
    // \u0063 escape for its leading "c"; it must still compare equal to
    // "command" once decoded.
    let escaped = r#"{"command":"echo probe","\u0063ommand":"rm -rf /"}"#;
    for (name, input) in [
        (
            "top level",
            r#"{"command":"echo probe","description":"x","command":"rm -rf /"}"#,
        ),
        ("escaped key", escaped),
        (
            "nested",
            r#"{"command":"echo probe","env":{"A":"1","A":"2"}}"#,
        ),
        ("in an array", r#"{"edits":[{"old":"a","old":"b"}]}"#),
    ] {
        let line = can_use_tool("", |q| {
            q.insert("input".to_string(), "@@INPUT@@".into());
        });
        let line = replace_once(&line, b"\"@@INPUT@@\"", input.as_bytes());
        let init_line = fixture_line(&fixture("bridge-allow.ndjson"), "system", "init");
        let r = start_raw(vec![init_line, line]).await;
        let events = collect(&*r.session, |_| {}).await;
        for e in &events {
            assert!(
                !matches!(
                    &e.payload,
                    Some(
                        EventPayload::PermissionRequested(_) | EventPayload::PermissionResolved(_)
                    )
                ),
                "{name}: an input with a duplicate key was bridged: {e:?}"
            );
        }
        let t = terminal_of(&events);
        assert_eq!(t.status, TerminalStatus::Failed, "{name}: {t:?}");
        assert_eq!(t.reason, claudecode::reasons::PERMISSION_BRIDGE_UNAVAILABLE);
        assert_eq!(
            r.tr.all().len(),
            2,
            "{name}: the adapter answered an input with a duplicate key: {:?}",
            r.tr.all()
        );
    }
}

/// `TestAnInputWithLargeNumbersIsBridged` — a number literal outside
/// float64's range, or one with many digits, is never itself a protocol
/// error (the `dec.UseNumber` point).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_with_large_numbers_is_bridged() {
    let input = r#"{"huge":1e999,"big":123456789012345678901234567890}"#;
    let line = can_use_tool("", |q| {
        q.insert("input".to_string(), "@@INPUT@@".into());
    });
    let line = replace_once(&line, b"\"@@INPUT@@\"", input.as_bytes());
    let r = start_with(
        &with_can_use_tool(&line),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect_answering(&r.session, false).await;
    let requested: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::PermissionRequested(p)) => Some(p.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(requested.len(), 1, "{requested:?}");
    assert_eq!(String::from_utf8_lossy(&requested[0].input), input);
}

/// `TestAnInputWithDistinctNestedKeysIsBridged` — the duplicate check
/// is per object: the same name in sibling or nested objects is fine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn input_with_distinct_nested_keys_is_bridged() {
    let input = r#"{"a":{"a":1},"b":[{"a":1},{"a":2}]}"#;
    let line = can_use_tool("", |q| {
        q.insert("input".to_string(), "@@INPUT@@".into());
    });
    let line = replace_once(&line, b"\"@@INPUT@@\"", input.as_bytes());
    let r = start_with(
        &with_can_use_tool(&line),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect_answering(&r.session, false).await;
    let requested: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.payload {
            Some(EventPayload::PermissionRequested(p)) => Some(p.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(requested.len(), 1, "{requested:?}");
    assert_eq!(String::from_utf8_lossy(&requested[0].input), input);
}

// =====================================================================
// live_usage_test.go — live usage reports and the fold
// =====================================================================

/// `TestLiveUsageReportsOfTheRealFixtures` — the live sums against the
/// three real success fixtures; every report folds cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_usage_reports_of_the_real_fixtures() {
    for (name, live, final_u) in [
        // Two messages: 35,555 billed tokens live against 35,755 in the
        // result.
        (
            "bridge-allow.ndjson",
            vec![
                cumulative(10, 3, 0, 34434, 0),
                cumulative(18, 5, 0, 35532, 0),
            ],
            cumulative(18, 205, 63842, 35532, 78491),
        ),
        (
            "success.ndjson",
            vec![cumulative(10, 6, 0, 34951, 0)],
            cumulative(10, 31, 13689, 34951, 71436),
        ),
        (
            "resume.ndjson",
            vec![cumulative(10, 5, 0, 80, 0)],
            cumulative(10, 241, 48640, 80, 77675),
        ),
    ] {
        let r = start_with(
            &fixture(name),
            start_spec(PermissionPolicy::Bridge),
            PlayOpts::default(),
        )
        .await;
        let events = collect_answering(&r.session, true).await;
        let reports = usage_reports(&events);
        let want: Vec<Usage> = live.iter().copied().chain([final_u]).collect();
        assert_eq!(reports, want, "{name}: usage reports");
        require_monotonic(&reports);
        assert_eq!(fold_usage(&reports), final_u, "{name}: folded");
        for e in &events {
            if matches!(&e.payload, Some(EventPayload::UsageReport(_))) {
                let raw = String::from_utf8_lossy(&e.raw);
                assert!(
                    raw.contains("\"type\":\"assistant\"") || raw.contains("\"type\":\"result\""),
                    "{name}: a usage report carries neither its assistant nor its result frame: {}",
                    raw
                );
            }
        }
        assert_eq!(
            terminal_of(&events).status,
            TerminalStatus::Succeeded,
            "{name}: terminal"
        );
    }
}

/// `TestLiveUsageCountsTheMainThreadOnce` — per message id the largest
/// value of each counter counts once; a subagent's frame, a frame
/// without an id or usage and a negative counter are not counted; a
/// frame that raises nothing is not reported; the result keeps a live
/// counter above its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_usage_counts_the_main_thread_once() {
    let fixture = [
        fixture_line(&fixture("success.ndjson"), "system", "init"),
        assistant_frame(
            Some("msg_A".into()),
            Some(tokens(100, 10, 50000, 9000)),
            None,
            true,
        ),
        // The same message again, with more output: out rises by 15.
        assistant_frame(
            Some("msg_A".into()),
            Some(tokens(100, 25, 50000, 9000)),
            None,
            true,
        ),
        // A subagent's message is not counted live.
        assistant_frame(
            Some("msg_S".into()),
            Some(tokens(7000, 7000, 70000, 0)),
            Some("toolu_task".into()),
            true,
        ),
        // No id, no usage, a negative counter: not counted.
        assistant_frame(None, Some(tokens(1, 1, 1, 0)), None, true),
        assistant_frame(Some("msg_U".into()), None, None, true),
        assistant_frame(Some("msg_N".into()), Some(tokens(-5, 1, 1, 0)), None, true),
        // No parent_tool_use_id field: the main thread.
        assistant_frame(
            Some("msg_B".into()),
            Some(tokens(5, 3, 1000, 0)),
            None,
            false,
        ),
        // msg_A once more with lower values: the largest seen counts.
        assistant_frame(
            Some("msg_A".into()),
            Some(tokens(50, 5, 100, 0)),
            None,
            true,
        ),
        // Below the live sum in tokens in (60 < 105) and cache write
        // (50999 < 51000), above it in tokens out (200 > 28).
        result_frame(tokens(60, 200, 50999, 12345), 0.5, 0),
    ]
    .concat();
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let reports = usage_reports(&events);
    let want = [
        cumulative(100, 10, 0, 50000, 0),
        cumulative(100, 25, 0, 50000, 0),
        cumulative(105, 28, 0, 51000, 0),
        cumulative(105, 200, 12345, 51000, 500000),
    ];
    assert_eq!(reports, want.as_slice(), "usage reports");
    require_monotonic(&reports);
    assert_eq!(fold_usage(&reports), want[3]);
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestALaterTurnIsNotAddedOnALiveInflatedBase` — a first result below
/// the live sum (a zeroed crash result) keeps the live figure, the next
/// message's live report carries that result's cost, and the last
/// report is the results' own sum raised to what was reported, never
/// the second result added on top of the live figure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_turn_is_not_added_on_a_live_inflated_base() {
    let fixture = [
        fixture_line(&fixture("success.ndjson"), "system", "init"),
        assistant_frame(
            Some("msg_A".into()),
            Some(tokens(1000, 10, 40000, 0)),
            None,
            true,
        ),
        result_frame(tokens(0, 0, 0, 0), 0.1, 1),
        assistant_frame(Some("msg_B".into()), Some(tokens(5, 2, 300, 0)), None, true),
        result_frame(tokens(20, 30, 700, 500), 0.2, 0),
    ]
    .concat();
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let reports = usage_reports(&events);
    let want = [
        cumulative(1000, 10, 0, 40000, 0),
        // The first result's own sum is 0 tokens: the live counters
        // stay.
        cumulative(1000, 10, 0, 40000, 100000),
        cumulative(1005, 12, 0, 40300, 100000),
        // The results sum to 20 in, 30 out, 500 read, 700 write: tokens
        // in and cache write stay at the live 1005 and 40300 (not 1025
        // and 41000), tokens out rise to 30.
        cumulative(1005, 30, 500, 40300, 200000),
    ];
    assert_eq!(reports, want.as_slice(), "usage reports");
    require_monotonic(&reports);
    assert_eq!(fold_usage(&reports), want[3]);
}

// =====================================================================
// result_report_test.go — the result frame is the report
// =====================================================================

/// `containsText`.
fn contains_text(texts: &[String], want: &str) -> bool {
    texts.iter().any(|t| t == want)
}

/// `TestTheResultFrameIsTheLastMessageNotASubagentsText` — a subagent's
/// text right before the result does not become the result's message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_frame_is_the_last_message_not_a_subagents_text() {
    let fixture = fixture("success.ndjson");
    let i = result_offset(&fixture);
    let mut injected = fixture[..i].to_vec();
    injected.extend_from_slice(SUBAGENT_FRAME);
    injected.extend_from_slice(&fixture[i..]);
    let r = start_with(
        &injected,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let (texts, after_usage) = messages_of(&events);
    assert_eq!(texts, ["OK", "SUBAGENT", "OK"], "messages = {texts:?}");
    assert!(after_usage);
    let last = &events[events.len() - 2];
    match &last.payload {
        Some(EventPayload::Message(m)) => {
            assert_eq!(m.text, "OK");
            assert!(String::from_utf8_lossy(&last.raw).contains("\"type\":\"result\""));
        }
        other => unreachable!("event before the terminal = {other:?}"),
    }
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
}

/// `TestAResultWithoutTextAddsNoMessage` — a result without usable text
/// adds no trailing Message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn result_without_text_adds_no_message() {
    for (name, exit) in [
        ("no result field", 0i32),
        ("empty result", 0),
        ("whitespace-only result", 0),
        ("error result", 1),
    ] {
        let fixture = mutate_result(&fixture("success.ndjson"), |r| match name {
            "no result field" => {
                r.remove("result");
            }
            "empty result" => {
                r.insert("result".to_string(), "".into());
            }
            "whitespace-only result" => {
                // A blank result must not override a non-blank last text
                // block: the report would then be blank.
                r.insert("result".to_string(), " \n\t ".into());
            }
            _ => {
                r.insert("is_error".to_string(), true.into());
                r.insert("subtype".to_string(), "error_during_execution".into());
                r.insert("terminal_reason".to_string(), "api_error".into());
            }
        });
        let r = start_with(
            &fixture,
            start_spec(PermissionPolicy::Bridge),
            PlayOpts {
                exit_code: exit,
                ..PlayOpts::default()
            },
        )
        .await;
        let events = collect(&*r.session, |_| {}).await;
        let (texts, after_usage) = messages_of(&events);
        assert_eq!(texts, ["OK"], "{name}: messages = {texts:?}");
        assert!(!after_usage, "{name}: message after usage");
    }
}

/// `TestErrorResultFixturesAddNoMessage` — an error or interrupted
/// result's text never becomes a Message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_result_fixtures_add_no_message() {
    // not authenticated.
    let r = start_with(
        &fixture("not-authenticated.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts {
            exit_code: 1,
            ..PlayOpts::default()
        },
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let (_, after_usage) = messages_of(&events);
    assert!(!after_usage, "an error result's text became a message");

    // interrupt: the interrupted result carries a result string, so
    // only the TerminalSucceeded guard keeps it from a Message.
    let fixture = mutate_result(&fixture("interrupt.ndjson"), |r| {
        r.insert("result".to_string(), "INTERRUPTED TEXT".into());
    });
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts {
            exit_code: 1,
            ..PlayOpts::default()
        },
    )
    .await;
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
        .await
        .expect("timed out collecting events")
    {
        e.validate().expect("invalid event");
        if let Some(EventPayload::PermissionRequested(p)) = &e.payload {
            let digest: [u8; 32] = Sha256::digest(&p.input).into();
            r.session
                .respond_permission(PermissionDecision {
                    request_id: p.request_id.clone(),
                    allow: true,
                    option_id: String::new(),
                    decided_by: String::new(),
                    input_sha256: digest,
                })
                .await
                .expect("respond");
            r.session.interrupt().await.expect("interrupt");
        }
        events.push(e);
    }
    let (texts, after_usage) = messages_of(&events);
    assert!(
        !after_usage && !contains_text(&texts, "INTERRUPTED TEXT"),
        "{texts:?}"
    );
    assert_eq!(terminal_of(&events).status, TerminalStatus::Interrupted);
}
