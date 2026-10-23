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
use central_foundation::identity::HarnessAttemptId;
use central_harness::domain::{Fence, PermissionPolicy, Terminal, TerminalStatus, Workspace};
use central_harness::event::{Event, EventKind, EventPayload};
use central_harness::port::{
    Adapter as _, ExitStatus, LaunchEnv, OperatorInput, PermissionDecision, PortFuture, Process,
    ProcessLauncher, ProcessSpec, Session, SessionRef, StartSpec,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
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

/// `scriptedProcess` — an in-memory `port.Process`: the script plays
/// fixture frames on stdout and reads what the adapter writes on stdin.
struct ScriptedProcess {
    scope: String,
    /// adapter → script (stdin)
    stdin_tx: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    stdin_rx: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    stdin_dead: AtomicBool,
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
        self.exited.notify_waiters();
    }

    /// Emit one fixture line on stdout (adds the newline).
    async fn emit_line(&self, line: &[u8]) -> Result<(), ()> {
        if self.status.lock().unwrap().is_some() {
            return Err(());
        }
        let mut l = line.to_vec();
        l.push(b'\n');
        let tx = self.stdout_tx.lock().unwrap().clone();
        match tx {
            Some(tx) => tx.send(l).map_err(|_| ()),
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
            if self.stdin_dead.load(Ordering::SeqCst) {
                return Err(Failure::new(
                    central_foundation::failure::FailureKind::Internal,
                    "E_IO",
                    "stdin closed",
                ));
            }
            let tx = self.stdin_tx.lock().unwrap().clone();
            match tx {
                Some(tx) => tx.send(buf.to_vec()).map(|_| buf.len()).map_err(|_| {
                    Failure::new(
                        central_foundation::failure::FailureKind::Internal,
                        "E_IO",
                        "stdin closed",
                    )
                }),
                None => Err(Failure::new(
                    central_foundation::failure::FailureKind::Internal,
                    "E_IO",
                    "stdin closed",
                )),
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
    auth_out: String,
    auth_code: i32,
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
            auth_out: String::new(),
            auth_code: 0,
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
                    stdout: Mutex::new(self.auth_out.as_bytes().to_vec()),
                    stderr: Mutex::new(b"email operator-probe@example.com\n".to_vec()),
                    code: self.auth_code,
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
    session: Box<dyn Session>,
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
    let s = a.start(spec).await.expect("start");
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

fn terminal_of(events: &[Event]) -> Terminal {
    events
        .iter()
        .find_map(|e| match &e.payload {
            Some(EventPayload::TerminalReported(t)) => Some(t.terminal.clone()),
            _ => None,
        })
        .expect("a terminal event")
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

/// `TestResume` — resume passes `--resume` and the fixture's id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn resume_fixture() {
    let tr = Transcript::default();
    let l = ScriptedLauncher::new(play_script(
        fixture("resume.ndjson"),
        tr.clone(),
        PlayOpts::default(),
    ));
    let a = new_adapter(l.clone());
    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.attempt = HarnessAttemptId::new();
    let s = a
        .resume(
            SessionRef {
                harness_session_id: FIXTURE_SESSION.to_string(),
            },
            spec,
        )
        .await
        .expect("resume");
    let events = collect(&*s, |_| {}).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    let launch = l.session_launches();
    assert!(
        launch[0]
            .args
            .windows(2)
            .any(|w| w == ["--resume", FIXTURE_SESSION])
    );
    assert!(!launch[0].args.iter().any(|a| a == "--session-id"));
}

/// `TestInterrupt` — the interrupt fixture waits for the host's
/// interrupt control request, then acks it; the run ends Interrupted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupt_fixture() {
    let r = start_with(
        &fixture("interrupt.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    // Read until the fixture's await marker is pending: the script
    // blocks until an interrupt frame arrives. Interrupt, then drain.
    r.session.interrupt().await.expect("interrupt");
    let events = collect(&*r.session, |_| {}).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Interrupted);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_ABORTED);
    // The interrupt control request was written.
    assert!(
        r.tr.frames()
            .iter()
            .any(|f| f["type"] == "control_request" && request_subtype(f) == "interrupt")
    );
}

/// `TestKill` — kill ends the process; the terminal is Killed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_ladder() {
    let fixture = b"{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"0192f000-0000-7000-8000-000000000001\",\"permissionMode\":\"default\",\"claude_code_version\":\"2.1.283\"}\n".to_vec();
    // No result: the script holds; kill ends it.
    let r = start_with(
        &fixture,
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    r.session.kill().await.expect("kill");
    let events = collect(&*r.session, |_| {}).await;
    let t = terminal_of(&events);
    assert_eq!(t.status, TerminalStatus::Killed);
    // The ladder may repeat the kill on the same handle (TERM → KILL).
    assert!(r.launcher.last_session().kill_count() >= 1);
}

/// `TestExitedWithoutResult` — EOF with no result frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exited_without_result() {
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
}

/// `TestNotAuthenticated` — the fixture ends with an api_error result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn not_authenticated_fixture() {
    let r = start_with(
        &fixture("not-authenticated.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let t = terminal_of(&events);
    // Upstream maps the authentication_failed frame/result to
    // harness_not_authenticated.
    assert_eq!(t.status, TerminalStatus::Failed);
    assert_eq!(t.reason, claudecode::reasons::HARNESS_NOT_AUTHENTICATED);
}

/// `TestMiscFrames` — stream_event, api_retry, rate_limit_event and
/// the control_response echo each map per upstream: api_retry becomes
/// a Retry event, the rest warnings or silence; no harness text leaks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn misc_frames() {
    let r = start_with(
        &fixture("misc-frames.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let k = kinds(&events);
    assert_eq!(k.first(), Some(&EventKind::SessionStarted));
    // api_retry → Retry; unknown frames → Warning.
    assert!(k.contains(&EventKind::Retry), "{k:?}");
    assert!(k.contains(&EventKind::Warning), "{k:?}");
    // No event text may carry the fixture's bait strings.
    for e in &events {
        let s = format!("{e:?}");
        assert!(!s.contains("must not leak"), "{s}");
    }
}

/// `TestPolicyDenied` — the deny-policy run: fixture ends with the
/// permission_denials result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_denied_fixture() {
    let r = start_with(
        &fixture("policy-denied.ndjson"),
        start_spec(PermissionPolicy::Deny),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    let t = terminal_of(&events);
    assert!(matches!(
        t.status,
        TerminalStatus::Succeeded | TerminalStatus::Failed
    ));
}

/// `TestAutoAllow` — the bypassPermissions run succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_allow_fixture() {
    let r = start_with(
        &fixture("auto-allow-success.ndjson"),
        start_spec(PermissionPolicy::AutoAllow),
        PlayOpts::default(),
    )
    .await;
    let events = collect(&*r.session, |_| {}).await;
    assert_eq!(terminal_of(&events).status, TerminalStatus::Succeeded);
    let launch = r.launcher.session_launches();
    assert!(
        launch[0]
            .args
            .windows(2)
            .any(|w| w == ["--permission-mode", "bypassPermissions"])
    );
}

// =====================================================================
// permission_bridge_test.go
// =====================================================================

/// `TestPermissionBridgeAllow` — the fixture's can_use_tool surfaces
/// PermissionRequested; an allow answers `allow` with the compacted
/// echoed input, then PermissionResolved lands and the run succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_allow_fixture() {
    let r = start_with(
        &fixture("bridge-allow.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    // Drive events until the request appears; the script waits for the
    // control_response before it can emit the rest of the fixture.
    let mut seen_req = None;
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let e = match tokio::time::timeout_at(deadline, r.session.next_event())
            .await
            .expect("timed out awaiting permission request")
        {
            Some(e) => e,
            None => break,
        };
        if let Some(EventPayload::PermissionRequested(req)) = &e.payload {
            seen_req = Some(req.clone());
        }
        collected.push(e);
        if seen_req.is_some() {
            break;
        }
    }
    let req = seen_req.expect("a permission request");
    assert_eq!(req.tool, "Bash");
    assert!(!req.input.is_empty());
    // Allow, bound to the exact echoed bytes.
    let digest = Sha256::digest(&req.input);
    r.session
        .respond_permission(PermissionDecision {
            request_id: req.request_id.clone(),
            allow: true,
            option_id: String::new(),
            decided_by: "operator-session:test".to_string(),
            input_sha256: digest.into(),
        })
        .await
        .expect("respond");
    // Drain the rest.
    while let Some(e) = r.session.next_event().await {
        collected.push(e);
    }
    let t = terminal_of(&collected);
    assert_eq!(t.status, TerminalStatus::Succeeded);
    assert!(collected.iter().any(|e| matches!(
        &e.payload,
        Some(EventPayload::PermissionResolved(r))
            if r.request_id == req.request_id
                && r.decision == central_harness::event::PermissionOutcome::Allowed
    )));
    // The allow response echoes the compacted input.
    assert!(r.tr.frames().iter().any(|f| {
        f["type"] == "control_response"
            && f["response"]["request_id"] == req.request_id
            && f["response"]["response"]["behavior"] == "allow"
    }));
}

/// `TestPermissionBridgeDeny` — a deny answers with the fixed text.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_deny_fixture() {
    let r = start_with(
        &fixture("bridge-deny.ndjson"),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    let mut req = None;
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while let Some(e) = tokio::time::timeout_at(deadline, r.session.next_event())
        .await
        .expect("timed out awaiting permission request")
    {
        if let Some(EventPayload::PermissionRequested(q)) = &e.payload {
            req = Some(q.clone());
            collected.push(e);
            break;
        }
        collected.push(e);
    }
    let req = req.expect("a permission request");
    r.session
        .respond_permission(PermissionDecision {
            request_id: req.request_id.clone(),
            allow: false,
            option_id: String::new(),
            decided_by: "operator-session:test".to_string(),
            input_sha256: [0; 32],
        })
        .await
        .expect("respond");
    while let Some(e) = r.session.next_event().await {
        collected.push(e);
    }
    assert!(r.tr.frames().iter().any(|f| {
        f["type"] == "control_response"
            && f["response"]["request_id"] == req.request_id
            && f["response"]["response"]["behavior"] == "deny"
            && f["response"]["response"]["message"] == "Denied by the operator."
    }));
}

// =====================================================================
// launch validation
// =====================================================================

/// `TestStartValidates` — the spec's PATH policy: absent and relative
/// entries are refused before any launch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn path_policy() {
    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.env.vars.clear();
    assert!(a.start(spec).await.is_err());

    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.env.vars.insert("PATH".to_string(), "bin".to_string());
    assert!(a.start(spec).await.is_err());

    let l = ScriptedLauncher::unscripted();
    let a = new_adapter(l);
    let mut spec = start_spec(PermissionPolicy::Bridge);
    spec.env
        .vars
        .insert("PATH".to_string(), "/usr/bin::/bin".to_string());
    assert!(a.start(spec).await.is_err());
}

/// `TestPinnedVersion` — a launcher reporting another version is
/// refused unless `allow_unpinned`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_version() {
    let l = ScriptedLauncher::unscripted();
    l.set_version("9.9.9 (Claude Code)\n");
    let a = new_adapter(l);
    assert!(a.start(start_spec(PermissionPolicy::Bridge)).await.is_err());

    let l = ScriptedLauncher::unscripted();
    l.set_version("9.9.9 (Claude Code)\n");
    let a = ClaudeCode::new(Config {
        launcher: Some(l),
        allow_unpinned: true,
        probe_work_dir: "/probe".to_string(),
        ..Config::default()
    })
    .unwrap();
    // Start proceeds; the unscripted process just sits until killed.
    let s = a.start(start_spec(PermissionPolicy::Bridge)).await.unwrap();
    s.kill().await.unwrap();
}

/// `send` writes a follow-up user frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_follow_up() {
    // Fixture: init, then an await marker for nothing — just emit a
    // delayed result so the send lands first. Use misc-frames minus
    // complications: craft inline.
    let fixture = format!(
        "{}\n{{\"central_fixture\":\"await\",\"request\":\"interrupt\"}}\n{{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"session_id\":\"{}\",\"queued_turn_count\":0}}\n",
        "{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"0192f000-0000-7000-8000-000000000001\",\"permissionMode\":\"default\",\"claude_code_version\":\"2.1.283\"}",
        SESSION_ID
    );
    let r = start_with(
        fixture.as_bytes(),
        start_spec(PermissionPolicy::Bridge),
        PlayOpts::default(),
    )
    .await;
    // The session is live once started; send, then interrupt to
    // release the fixture's await marker.
    r.session
        .send(OperatorInput {
            text: "follow up".to_string(),
        })
        .await
        .expect("send");
    r.session.interrupt().await.expect("interrupt");
    let _ = collect(&*r.session, |_| {}).await;
    assert!(r.tr.all().iter().any(|l| l.contains("\"follow up\"")));
}
